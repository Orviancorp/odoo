# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import logging
import re
from odoo import api, fields, models, _
from odoo.exceptions import ValidationError

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
                                 help="Hierarchical subdomain.")
    
    # Needs to be a char for now, as requested. 
    base_domain = fields.Char(string='Base Domain',
                              help="Base domain for the tenant.")
    
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
            if tenant.parent_id:
                # Use sudo to access parent's full_subdomain if needed, though robust compute should be fine
                tenant.full_subdomain = f"{tenant.subdomain}.{tenant.parent_id.full_subdomain}" if tenant.parent_id.full_subdomain else f"{tenant.subdomain}.{tenant.parent_id.subdomain}"
            else:
                tenant.full_subdomain = tenant.subdomain

    @api.depends('full_subdomain', 'base_domain')
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
