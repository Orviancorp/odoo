# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import logging
import re
import requests
import os
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
            if len(tenant.subdomain) < 3 or len(tenant.subdomain) > 63:
                raise ValidationError(_("Subdomain validation error: length must be between 3 and 63 characters."))

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

            self.action_generate_origin_certificate()

        except requests.exceptions.RequestException as e:
            raise UserError(_("Failed to connect to Cloudflare: %s") % str(e))

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

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _("Cleanup Complete"),
                'message': _("Deleted %s orphan DNS records.") % deleted_count,
                'type': 'success',
                'sticky': False,
            }
        }

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

        if not os.path.exists(certs_path):
            try:
                os.makedirs(certs_path)
            except OSError as e:
                raise UserError(_("Failed to create certificates directory: %s") % str(e))

        success_count = 0
        for tenant in self:
            if not tenant.full_domain:
                continue

            # Check if cert already exists
            safe_name = tenant.full_domain.replace('*', 'wildcard')
            combined_filename = os.path.join(certs_path, f"{safe_name}.pem")
            
            if os.path.exists(combined_filename):
                _logger.info("Certificate for %s already exists at %s. Skipping.", tenant.full_domain, combined_filename)
                continue

            # Cloudflare Origin CA API
            url = "https://api.cloudflare.com/client/v4/certificates"
            headers = {
                "Authorization": f"Bearer {api_token}", # Ensure Token has 'Zone.Origin CA' permission
                "Content-Type": "application/json"
            }
            # Payload: 15 years validity (5475 days), RSA, for the single host
            data = {
                "hostnames": [tenant.full_domain],
                "requested_validity": 5475,
                "request_type": "origin-rsa",
                "csr": None # Let CF generate the keypair
            }

            try:
                response = requests.post(url, json=data, headers=headers)
                _logger.info(response)
                response.raise_for_status()
                result = response.json()
               
                if not result.get('success'):
                    errors = result.get('errors', [])
                    msg = ", ".join([e.get('message', 'Unknown error') for e in errors])
                    _logger.error("Certificate generation failed for %s: %s", tenant.full_domain, msg)
                    # We might want to raise error or continue? 
                    # If multiple selected, continue and log.
                    continue
                
                cert_data = result['result']
                certificate = cert_data['certificate']
                private_key = cert_data['private_key']
                
                with open(combined_filename, 'w') as f:
                    f.write(private_key)
                    # Ensure newline separation
                    if not private_key.endswith('\n'):
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
