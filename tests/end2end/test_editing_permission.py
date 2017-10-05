# -*- coding: utf-8 -*-
"""Test editing permissions."""

from __future__ import absolute_import, division, print_function, unicode_literals

from flask import url_for
from flask_babel import gettext as _
from jinja2 import escape

from xl_auth.permission.models import Permission

from ..factories import CollectionFactory, PermissionFactory


# noinspection PyUnusedLocal
def test_user_can_edit_existing_permission(user, permission, testapp):
    """Edit existing permission."""
    old_count = len(Permission.query.all())
    other_collection = CollectionFactory()
    # Goes to homepage
    res = testapp.get('/')
    # Fills out login form in navbar
    form = res.forms['loginForm']
    form['username'] = user.email
    form['password'] = 'myPrecious'
    # Submits
    form.submit().follow()
    # Clicks Permissions button
    res = res.click(_('Permissions'))
    # Clicks Edit button on a permission
    res = res.click(_('Edit'))
    # Fills out the form
    form = res.forms['editPermissionForm']
    # Defaults are kept -- setting ``form['user_id'] = permission.user.id`` is redundant.
    form['collection_id'] = other_collection.id
    # Submits
    res = form.submit().follow()
    assert res.status_code == 200
    # Number of permissions are the same
    assert len(Permission.query.all()) == old_count
    # The edited permission is listed under existing collections
    assert '<td>{}</td>'.format(permission.user.email) in res
    assert '<td>{}</td>'.format(other_collection.code) in res


# noinspection PyUnusedLocal
def test_user_sees_error_message_if_permission_is_already_registered(user, permission, testapp):
    """Show error if permission is edited to (user_id, collection_id) pair that already exists."""
    other_permission = PermissionFactory()
    # Goes to homepage
    res = testapp.get('/')
    # Fills out login form in navbar
    form = res.forms['loginForm']
    form['username'] = user.email
    form['password'] = 'myPrecious'
    # Submits
    form.submit().follow()
    # Clicks Permissions button
    res = res.click(_('Permissions'))
    # Clicks Edit button on 'permission'
    permission_url = url_for('permission.edit', permission_id=permission.id)
    res = res.click(_('Edit'), href=permission_url)
    # Fills out the form with same user ID and collection ID as 'other_permission'
    form = res.forms['editPermissionForm']
    form['user_id'] = other_permission.user.id
    form['collection_id'] = other_permission.collection.id
    # Submits
    res = form.submit()
    # Sees error
    assert escape(
        _('Permissions for user "%(username)s" on collection "%(code)s" already registered',
          username=other_permission.user.email, code=other_permission.collection.code)) in res
