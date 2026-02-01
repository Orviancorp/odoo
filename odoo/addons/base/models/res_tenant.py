# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import logging
import re
import requests
import os
import glob
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from odoo import api, fields, models, _
from odoo.exceptions import ValidationError, UserError

_logger = logging.getLogger(__name__)


class ResTenant(models.Model):
    _name = "res.tenant"
    _description = "Tenant"
    _order = "sequence, name"
    _parent_store = True

    name = fields.Char(string='Name', required=True, index=True)
    active = fields.Boolean(default=True)
    sequence = fields.Integer(default=10)

    # Hierarchy
    parent_id = fields.Many2one('res.tenant', string='Parent Tenant', index=True, ondelete='cascade')
    child_ids = fields.One2many('res.tenant', 'parent_id', string='Child Tenants')
    parent_path = fields.Char(index=True)

    # Identity / Domain
    subdomain = fields.Char(string='Subdomain', required=True, index=True,
                            help="Slug used for tenant identification.")
    full_subdomain = fields.Char(string='Full Subdomain', compute='_compute_full_subdomain', store=True, index=True,
                                 recursive=True, help="Hierarchical subdomain.")
    
    # Needs to be a char for now, as requested. 
    base_domain = fields.Char(string='Base Domain',
                              help="Base domain for the tenant.", compute='_compute_base_domain', store=False)
    
    full_domain = fields.Char(string='Full Domain', compute='_compute_full_domain', store=True, index=True, readonly=True,
                              help="Complete domain URL.")
    
    url = fields.Char(string='URL', compute='_compute_url', store=True,
                      help="Full URL for the tenant.")

    # Access
    user_ids = fields.Many2many('res.users', string='Users', help="Users allowed to access this tenant.")
    user_count = fields.Integer(string='User Count', compute='_compute_user_count')

    _sql_constraints = [
        ('subdomain_unique_parent', 'unique(parent_id, subdomain)', 'The subdomain must be unique within the same parent tenant (or root)!'),
        ('full_domain_unique', 'unique(full_domain)', 'The Full Domain must be unique!'),
    ]


    def _compute_base_domain(self):
        config = self.env['ir.config_parameter'].sudo()
        main_system_url = config.get_param('base.main_system_url')
        for tenant in self:
            tenant.base_domain = main_system_url

    @api.constrains('parent_id')
    def _check_parent_id(self):
        if not self._check_recursion():
            raise ValidationError(_('You cannot create recursive hierarchy.'))

    @api.constrains('subdomain')
    def _check_subdomain(self):
        for tenant in self:
            if not re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', tenant.subdomain):
                raise ValidationError(_("Subdomain must be 'slug-safe': lowercase letters, numbers, and hyphens only. It cannot start or end with a hyphen."))

    @api.depends('subdomain', 'parent_id.full_subdomain')
    def _compute_full_subdomain(self):
        for tenant in self:
            if tenant.parent_id and tenant.parent_id.full_subdomain:
                tenant.full_subdomain = f"{tenant.subdomain}.{tenant.parent_id.full_subdomain}"
            else:
                tenant.full_subdomain = tenant.subdomain

    @api.depends('full_subdomain')
    def _compute_full_domain(self):
        for tenant in self:
            if tenant.full_subdomain and tenant.base_domain:
                tenant.full_domain = f"{tenant.full_subdomain}.{tenant.base_domain}"
            else:
                tenant.full_domain = False

    @api.depends('full_domain')
    def _compute_url(self):
        for tenant in self:
            if tenant.full_domain:
                tenant.url = f"https://{tenant.full_domain}"
            else:
                tenant.url = False

    @api.depends('user_ids')
    def _compute_user_count(self):
        for tenant in self:
            tenant.user_count = len(tenant.user_ids)

    def action_update_dns(self):
        self.ensure_one()
        config = self.env['ir.config_parameter'].sudo()
        api_token = config.get_param('base.cloudflare_api_token')
        zone_id = config.get_param('base.cloudflare_zone_id')
        main_url = self.base_domain

        if not api_token or not zone_id or not main_url:
            return

        if not self.full_subdomain:
            return

        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        data = {
            "type": "CNAME",
            "name": self.full_subdomain,
            "content": main_url,
            "ttl": 1,  # Auto
            "proxied": True
        }

        try:
            response = requests.post(url, json=data, headers=headers)
            # Check for HTTP errors first
            response.raise_for_status()
            
            result = response.json()
            if not result.get('success'):
                errors = result.get('errors', [])
                msg = ", ".join([e.get('message', 'Unknown error') for e in errors])
                raise UserError(_("Cloudflare API Error: %s") % msg)

        except requests.exceptions.RequestException as e:
            _logger.error(_("Failed to connect to Cloudflare: %s") % str(e))

        self.action_generate_origin_certificate()

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _("Success"),
                'message': _("DNS Record created successfully!"),
                'type': 'success',
                'sticky': False,
            }
        }

    @api.model
    def action_cleanup_orphan_dns_records(self):
        """
        Deletes Cloudflare CNAME records that point to the main system URL
        but do not correspond to any existing Tenant's full_subdomain.
        This is a global cleanup action.
        """
        config = self.env['ir.config_parameter'].sudo()
        api_token = config.get_param('base.cloudflare_api_token')
        zone_id = config.get_param('base.cloudflare_zone_id')
        main_url = config.get_param('base.main_system_url')

        # If any of the required parameters are missing, return without doing anything because the DNS record will not be created
        if not api_token or not zone_id or not main_url:
            return

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

        # 1. Get Zone Details to determine Zone Name (e.g. domain.com)
        try:
            zone_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
            zone_resp = requests.get(zone_url, headers=headers)
            zone_resp.raise_for_status()
            zone_data = zone_resp.json()
            if not zone_data.get('success'):
                raise UserError(_("Failed to fetch Zone details."))
            zone_name = zone_data['result']['name']
        except requests.exceptions.RequestException as e:
            raise UserError(_("Failed to connect to Cloudflare: %s") % str(e))
        
        # 2. Get all valid Full Subdomains (FQDNs) from Tenants
        # Logic: full_subdomain in Odoo does not include the base domain usually.
        # This cleanup assumes tenants ARE using the zone as base.
        
        # Safer approach:
        # CF Record Name is always FQDN.
        # Odoo Tenant `full_subdomain` is the relative part (usually).
        # So we expect Record Name == tenant.full_domain

        valid_fqdns = set()
        tenants = self.sudo().search([('full_domain', '!=', False)])
        for t in tenants:
            valid_fqdns.add(t.full_domain)

        # 3. List all CNAME records pointing to main_url
        to_delete = set()
        already_exists = set()
        page = 1
        
        while True:
            params = {
                'type': 'CNAME', 
                'content': main_url, 
                'page': page, 
                'per_page': 100
            }
            try:
                list_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
                resp = requests.get(list_url, headers=headers, params=params)
                resp.raise_for_status()
                data = resp.json()
                
                if not data.get('success'):
                     break # Should handle error?
                     
                records = data.get('result', [])
                if not records:
                    break
                    
                for record in records:
                    # Record name is FQDN
                    if record['name'] not in valid_fqdns:
                        to_delete.add(record['id'])
                    else:
                        already_exists.add(record['name'])

                info = data.get('result_info', {})
                total_pages = info.get('total_pages', 1)
                
                if page >= total_pages:
                    break
                page += 1
                
            except requests.exceptions.RequestException:
                break # Fail safely

        # 4. Delete Orphans
        deleted_count = 0
        for rec_id in to_delete:
            try:
                del_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}"
                requests.delete(del_url, headers=headers)
                deleted_count += 1
            except:
                pass # Continue trying to delete others

        # 5. Insert Missing
        _logger.info(valid_fqdns)
        _logger.info(already_exists)
        tenants_to_insert = tenants.filtered(lambda t: t.full_domain in valid_fqdns and t.full_domain not in already_exists)
        _logger.info(tenants_to_insert)
        for t in tenants_to_insert:
            t.action_update_dns()
            
        # 6. Cleanup Orphan Certificates
        deleted_certs = self._cleanup_orphan_certificates(config)

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _("Cleanup Complete"),
                'message': _("Deleted %s orphan DNS records and %s orphan certificates.") % (deleted_count, deleted_certs),
                'type': 'success',
                'sticky': False,
            }
        }

    def _cleanup_orphan_certificates(self, config):
        """
        Deletes certificate files (.pem) that do not correspond to any active tenant.
        Does NOT delete the certificate for the Main System URL.
        """
        certs_path = config.get_param('base.cloudflare_certs_path')
        # add / at the end of the path if it's not there
        if not certs_path.endswith('/'):
            certs_path += '/' 
        certs_path_deleted = certs_path + 'deleted/' 
        main_url = config.get_param('base.main_system_url')
        
        if not certs_path or not os.path.exists(certs_path):
            return 0

        # Ensure deleted directory exists
        if not os.path.exists(certs_path_deleted):
            try:
                os.makedirs(certs_path_deleted)
            except OSError as e:
                _logger.error("Failed to create deleted certificates directory: %s", e)
                return 0
            
        # 1. Allowlist: Active Tenants + Main URL
        allowlist = set()
        if main_url:
             # Add main URL and wildcard variant
            allowlist.add(main_url)

        tenants = self.sudo().search([('full_domain', '!=', False)])
        for t in tenants:
            full_domain = t.full_domain
            # Logic must match generation: if parent, we generate/keep parent domain cert
            if t.parent_id:
                full_domain = t.parent_id.full_domain
            
            allowlist.add(full_domain)

        _logger.info("Certificate Cleanup Allowlist: %s", allowlist)
        
        # 2. Iterate and Delete
        deleted_count = 0
        # Check all .pem files
        files = glob.glob(os.path.join(certs_path, "*.pem"))
        for file_path in files:
            filename = os.path.basename(file_path)
            # Remove extension to get "domain" or "safe_name"
            # Logic: We stored as `safe_name.pem`. 
            # So if `safe_name` is in allowlist, keep it.
            name_no_ext = os.path.splitext(filename)[0]
            if name_no_ext not in allowlist:
                try:
                    os.rename(file_path, os.path.join(certs_path_deleted, filename))
                    _logger.info("Deleted orphan certificate: %s", file_path)
                    deleted_count += 1
                except OSError as e:
                    _logger.error("Failed to delete certificate %s: %s", file_path, e)
                    
        return deleted_count

    def action_generate_origin_certificate(self):
        """
        Generates a Cloudflare Origin CA Certificate for the tenant's full_domain 
        and saves it to the configured path.
        """
        config = self.env['ir.config_parameter'].sudo()
        api_token = config.get_param('base.cloudflare_api_token')
        certs_path = config.get_param('base.cloudflare_certs_path')
        
        if not api_token or not certs_path:
            return

        # Ensure paths end with separator or use os.path.join
        # But keeping user logic roughly same:
        if not certs_path.endswith(os.path.sep):
             certs_path += os.path.sep
        
        certs_path_deleted = os.path.join(certs_path, 'deleted')

        if not os.path.exists(certs_path):
            try:
                os.makedirs(certs_path)
            except OSError as e:
                raise UserError(_("Failed to create certificates directory: %s") % str(e))

        if not os.path.exists(certs_path_deleted):
            try:
                os.makedirs(certs_path_deleted)
            except OSError as e:
                raise UserError(_("Failed to create deleted certificates directory: %s") % str(e))

        success_count = 0
        for tenant in self:
            if not tenant.full_domain:
                continue

            # Generate for parent_id *.parent_id.full_domain or *.full_domain if no parent_id
            full_domain = tenant.full_domain
            if tenant.parent_id:
                full_domain = tenant.parent_id.full_domain

            # Check if cert already exists
            safe_name = full_domain.replace('*', 'wildcard')
            combined_filename = os.path.join(certs_path, f"{safe_name}.pem")
            
            if os.path.exists(combined_filename):
                _logger.info("Certificate for %s already exists at %s. Skipping.", full_domain, combined_filename)
                continue

            # Check if exists in deleted folder and restore
            deleted_filename = os.path.join(certs_path_deleted, f"{safe_name}.pem")
            if os.path.exists(deleted_filename):
                try:
                    os.rename(deleted_filename, combined_filename)
                    _logger.info("Certificate for %s restored from %s.", full_domain, deleted_filename)
                    success_count += 1
                except OSError as e:
                    _logger.error("Failed to restore certificate for %s: %s", full_domain, e)
                continue

            # 1. Generate Private Key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # 2. Generate CSR
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, full_domain),
            ])).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(full_domain),
                    x509.DNSName(f"*.{full_domain}"),
                ]),
                critical=False,
            ).sign(key, hashes.SHA256(), default_backend())

            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            # Serialize Private Key for saving later
            private_key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            # 3. Cloudflare Origin CA API
            url = "https://api.cloudflare.com/client/v4/certificates"
            headers = {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json"
            }
            
            # Payload: CSR is required. request_type=origin-rsa matches the CSR key type.
            data = {
                "hostnames": [full_domain, f"*.{full_domain}"],
                "requested_validity": 5475,
                "request_type": "origin-rsa",
                "csr": csr_pem
            }

            try:
                response = requests.post(url, json=data, headers=headers)
                # _logger.info(response.text)
                response.raise_for_status()
                result = response.json()
                
                if not result.get('success'):
                    errors = result.get('errors', [])
                    msg = ", ".join([e.get('message', 'Unknown error') for e in errors])
                    _logger.error("Certificate generation failed for %s: %s", full_domain, msg)
                    continue
                
                cert_data = result['result']
                certificate = cert_data['certificate']
                # Cloudflare returns the certificate. We use our local private key.
                
                with open(combined_filename, 'w') as f:
                    f.write(private_key_pem)
                    if not private_key_pem.endswith('\n'):
                        f.write('\n')
                    f.write(certificate)
                    
                success_count += 1
                
            except requests.exceptions.RequestException as e:
                raise UserError(_("Connection Error: %s") % str(e))
            except IOError as e:
                 raise UserError(_("Failed to write certificate files: %s") % str(e))

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _("Certificate Generation"),
                'message': _("Generated %s certificates.") % success_count,
                'type': 'success',
                'sticky': False,
            }
        }
