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
    _order = "parent_path"
    _parent_store = True

    name = fields.Char(string='Name', required=True, index=True)
    active = fields.Boolean(default=True)
    sequence = fields.Integer(default=10)

    # Hierarchy
    parent_id = fields.Many2one('res.tenant', string='Parent Tenant', index=True, ondelete='cascade')
    child_ids = fields.One2many('res.tenant', 'parent_id', string='Child Tenants')
    parent_path = fields.Char(index=True)

    # Identity / Domain
    subdomain = fields.Char(string='Subdomain', required=False, index=True,
                            help="Slug used for tenant identification.")
    full_subdomain = fields.Char(string='Full Subdomain', compute='_compute_full_subdomain', store=True, index=True,
                                 recursive=True, help="Hierarchical subdomain.")
    
    # Needs to be a char for now, as requested. 
    # Base Domain: Editable for Root, Inherited for Child
    base_domain = fields.Char(string='Base Domain', help="Base domain for the tenant (e.g. orviancorp.com).", 
                              compute='_compute_base_domain', store=True, readonly=False)
    
    # Cloudflare Settings (Root Tenant only)
    cloudflare_api_token = fields.Char(string="Cloudflare API Token", help="API Token with DNS Edit permissions. Only for Root Tenants.")
    cloudflare_zone_id = fields.Char(string="Cloudflare Zone ID", help="The Zone ID for the domain in Cloudflare. Only for Root Tenants.")
    cloudflare_certs_path = fields.Char(string="Certificates Path", help="Directory path to save Cloudflare Origin Certificates. Only for Root Tenants.")
    
    def _default_port(self):
        if self.env.context.get('default_parent_id'):
            parent = self.env['res.tenant'].browse(self.env.context['default_parent_id'])
            # Traverse to root
            root = parent
            while root.parent_id:
                root = root.parent_id
            return root.port or 443
        return 443

    full_domain = fields.Char(string='Full Domain', compute='_compute_full_domain', store=True, index=True, readonly=True,
                              help="Complete domain URL.")
    
    port = fields.Integer(string='Port', default=_default_port, required=True, help="Port number for the tenant URL.")

    url = fields.Char(string='URL', compute='_compute_url', store=True,
                      help="Full URL for the tenant.")

    # Access
    user_ids = fields.Many2many('res.users', string='Users', help="Users allowed to access this tenant.")
    user_count = fields.Integer(string='User Count', compute='_compute_user_count')

    _sql_constraints = [
        ('subdomain_unique_parent', 'unique(parent_id, subdomain)', 'The subdomain must be unique within the same parent tenant (or root)!'),
        ('full_domain_unique', 'unique(full_domain)', 'The Full Domain must be unique!'),
    ]


    @api.depends('parent_id', 'parent_id.base_domain')
    def _compute_base_domain(self):
        for tenant in self:
            if tenant.parent_id:
                tenant.base_domain = tenant.parent_id.base_domain
            # If root, we rely on user input (or stored value). 
            # Compute method usually overwrites if strictly computed. 
            # With store=True + readonly=False, it triggers only on dependency change.
            elif not tenant.base_domain:
                tenant.base_domain = False

    @api.constrains('parent_id')
    def _check_parent_id(self):
        if not self._check_recursion():
            raise ValidationError(_('You cannot create recursive hierarchy.'))

    @api.constrains('subdomain', 'parent_id')
    def _check_subdomain(self):
        for tenant in self:
            if tenant.parent_id and not tenant.subdomain:
                raise ValidationError(_("Subdomain is required for Child Tenants."))
                
            if tenant.subdomain and not re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', tenant.subdomain):
                raise ValidationError(_("Subdomain must be 'slug-safe': lowercase letters, numbers, and hyphens only. It cannot start or end with a hyphen."))

    @api.onchange('parent_id')
    def _onchange_parent_id(self):
        for tenant in self:
            if tenant.parent_id:
                # Traverse to root to find the port, similar to default logic
                root = tenant.parent_id
                while root.parent_id:
                    root = root.parent_id
                tenant.port = root.port or tenant.port or 443
                
                # Also inherit base_domain if parent set
                tenant.base_domain = tenant.parent_id.base_domain

    @api.depends('subdomain', 'parent_id.full_subdomain')
    def _compute_full_subdomain(self):
        for tenant in self:
            if tenant.parent_id and tenant.parent_id.full_subdomain:
                tenant.full_subdomain = f"{tenant.subdomain}.{tenant.parent_id.full_subdomain}"
            else:
                tenant.full_subdomain = tenant.subdomain or False

    @api.depends('full_subdomain', 'base_domain')
    def _compute_full_domain(self):
        for tenant in self:
            if tenant.base_domain:
                if tenant.full_subdomain:
                    tenant.full_domain = f"{tenant.full_subdomain}.{tenant.base_domain}"
                else:
                    tenant.full_domain = tenant.base_domain
            else:
                tenant.full_domain = False

    @api.depends('full_domain', 'port')
    def _compute_url(self):
        for tenant in self:
            if tenant.full_domain:
                if tenant.port and tenant.port != 443:
                    tenant.url = f"https://{tenant.full_domain}:{tenant.port}"
                else:
                    tenant.url = f"https://{tenant.full_domain}"
            else:
                tenant.url = False

    @api.depends('user_ids')
    def _compute_user_count(self):
        for tenant in self:
            tenant.user_count = len(tenant.user_ids)

    def action_update_dns(self):
        self.ensure_one()
        
        # Find Root Tenant for configuration
        root = self
        while root.parent_id:
            root = root.parent_id
            
        api_token = root.cloudflare_api_token
        zone_id = root.cloudflare_zone_id
        main_url = root.base_domain

        if not api_token or not zone_id or not main_url:
            raise UserError(_("Cloudflare settings (Token, Zone ID, or Base Domain) are missing on the Root Tenant."))

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
        Deletes Cloudflare CNAME records that point to the main system URL.
        Iterates over all Root Tenants to handle multiple zones/domains.
        """
        root_tenants = self.search([('parent_id', '=', False)])
        total_deleted_dns = 0
        total_deleted_certs = 0
        
        for root in root_tenants:
            deleted_dns, deleted_certs = self._cleanup_root_tenant(root)
            total_deleted_dns += deleted_dns
            total_deleted_certs += deleted_certs

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _("Cleanup Complete"),
                'message': _("Deleted %s orphan DNS records and %s orphan certificates.") % (total_deleted_dns, total_deleted_certs),
                'type': 'success',
                'sticky': False,
            }
        }

    def _cleanup_root_tenant(self, root):
        api_token = root.cloudflare_api_token
        zone_id = root.cloudflare_zone_id
        main_url = root.base_domain

        if not api_token or not zone_id or not main_url:
            return 0, 0

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

        # 1. Get Zone Details (Optional verify) - skipping for speed/simplicity
        
        # 2. Get valid FQDNs for THIS root's children (and root itself)
        # Assuming all descendants share the same zone/domain logic?
        # Actually, if we have multiple roots, we only care about tenants under THIS root.
        
        # Helper to get all descendants
        # Odoo's parent_store makes searching children easy usually, but let's use search with parent_id hierarchy
        # Or easier: domain search
        # Using 'child_of' operator
        family = self.search([('id', 'child_of', root.id)])
        valid_fqdns = set(t.full_domain for t in family if t.full_domain)
        
        # 3. List all CNAME records for this zone pointing to main_url
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
                     break 
                     
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
                break 

        # 4. Delete Orphans
        deleted_count = 0
        for rec_id in to_delete:
            try:
                del_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}"
                requests.delete(del_url, headers=headers)
                deleted_count += 1
            except:
                pass 

        # 5. Insert Missing
        tenants_to_insert = family.filtered(lambda t: t.full_domain and t.full_domain not in already_exists)
        for t in tenants_to_insert:
            # We call action_update_dns which now uses root settings correctly
            # Note: t.root is 'root' here.
            try:
                t.action_update_dns()
            except:
                pass # Fail silently during batch cleanup
            
        # 6. Cleanup Orphan Certificates for this root
        deleted_certs = self._cleanup_orphan_certificates(root)
        
        return deleted_count, deleted_certs

    def _cleanup_orphan_certificates(self, root):
        """
        Deletes certificate files (.pem) that do not correspond to any active tenant.
        Does NOT delete the certificate for the Main System URL.
        """
        config = root # Renaming for minimal diff if needed, but better to use root
        certs_path = root.cloudflare_certs_path
        # add / at the end of the path if it's not there
        if not certs_path or not certs_path.endswith('/'):
             if certs_path:
                certs_path += '/' 
        
        main_url = root.base_domain
        
        certs_path_deleted = certs_path + 'deleted/' 
        
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
        success_count = 0
        
        # Group tenants by Root to optimize setting retrieval? 
        # Or just iterate and find root for each (safe).
        
        for tenant in self:
            if not tenant.full_domain:
                continue

            # Find Root
            root = tenant
            while root.parent_id:
                root = root.parent_id
                
            api_token = root.cloudflare_api_token
            certs_path = root.cloudflare_certs_path

            if not api_token or not certs_path:
                _logger.warning("Cloudflare settings missing for root tenant %s. Skipping %s.", root.name, tenant.name)
                continue

            # Ensure paths end with separator or use os.path.join
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

            # Generate for parent_id *.parent_id.full_domain or *.full_domain if no parent_id
            full_domain = tenant.full_domain
            if tenant.parent_id:
                full_domain = tenant.parent_id.full_domain

            # Check if cert already exists
            combined_filename = os.path.join(certs_path, f"{full_domain}.pem")
            
            if os.path.exists(combined_filename):
                _logger.info("Certificate for %s already exists at %s. Skipping.", full_domain, combined_filename)
                continue

            # Check if exists in deleted folder and restore
            deleted_filename = os.path.join(certs_path_deleted, f"{full_domain}.pem")
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
