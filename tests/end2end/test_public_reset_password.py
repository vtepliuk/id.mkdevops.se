# -*- coding: utf-8 -*-
"""Test resetting forgotten password."""

from __future__ import absolute_import, division, print_function, unicode_literals

from datetime import datetime, timedelta

from flask import url_for
from flask_babel import gettext as _
from jinja2 import escape

from xl_auth.extensions import mail
from xl_auth.user.models import PasswordReset


def test_can_complete_password_reset_flow(user, testapp):
    """Successfully request password reset and use the code to change password."""
    # Goes to homepage.
    res = testapp.get('/')
    # Clicks on 'Forgot password'.
    res = res.click(_('Forgot password?'))
    # Fills out ForgotPasswordForm.
    username_with_different_casing = user.email.upper()
    form = res.forms['forgotPasswordForm']
    form['username'] = username_with_different_casing
    # Submits.
    with mail.record_messages() as outbox:
        res = form.submit().follow()
        assert res.status_code == 200
        assert len(outbox) == 1
        reset_password_email = outbox[0]

    # New PasswordReset is added to DB.
    password_reset = PasswordReset.query.filter_by(user=user).first()
    assert password_reset.is_active is True
    assert password_reset.expires_at > (datetime.utcnow() + timedelta(seconds=3600))

    # URL sent to user email.
    reset_password_url = url_for('public.reset_password', email=password_reset.user.email,
                                 code=password_reset.code, _external=True)
    assert reset_password_email.recipients == [user.email]
    assert reset_password_email.sender == 'noreply@kb.se'
    assert reset_password_email.reply_to == 'libris@kb.se'
    assert reset_password_email.subject == _('Password reset for %(username)s at %(server_name)s',
                                             username=user.email, server_name='localhost')
    assert reset_password_url in reset_password_email.body
    assert reset_password_url in reset_password_email.html

    # Goes to reset password link.
    res = testapp.get(reset_password_url)
    # Fills out ResetPasswordForm.
    form = res.forms['resetPasswordForm']
    form['confirm'] = form['password'] = 'unicorns are real'
    # Submits.
    res = form.submit().follow()
    assert res.status_code == 200

    # PasswordReset no longer active and password update succeeded.
    updated_password_reset = PasswordReset.query.filter_by(user=password_reset.user).first()
    assert updated_password_reset.is_active is False
    assert updated_password_reset.user.check_password('unicorns are real') is True


# noinspection PyUnusedLocal
def test_sees_error_message_if_username_does_not_exist(user, testapp):
    """Show error if username doesn't exist."""
    # Goes to 'Forgot Password?' page.
    res = testapp.get(url_for('public.forgot_password'))
    # Fills out ForgotPasswordForm.
    form = res.forms['forgotPasswordForm']
    form['username'] = 'unknown@example.com'
    # Submits.
    res = form.submit()
    # Sees error.
    assert _('Unknown username/email') in res

    # No PasswordReset is added.
    password_reset = PasswordReset.query.filter_by(user=user).first()
    assert password_reset is None


# noinspection PyUnusedLocal
def test_sees_error_message_if_username_does_not_match_exist(user, password_reset, testapp):
    """Show error if username doesn't match code when resetting."""
    assert user != password_reset.user

    # Goes to reset password link.
    res = testapp.get(url_for('public.reset_password', email=user.email,
                              code=password_reset.code))
    # Fills out ResetPasswordForm.
    form = res.forms['resetPasswordForm']
    form['confirm'] = form['password'] = 'superSecret'
    # Submits.
    res = form.submit()
    # Sees error.
    assert escape(_('Reset code "%(code)s" does not exit', code=password_reset.code)) in res


# noinspection PyUnusedLocal
def test_sees_error_message_if_reset_code_is_expired(password_reset, testapp):
    """Show error if reset code has expired."""
    password_reset.expires_at = datetime.utcnow() - timedelta(seconds=1)
    password_reset.save()
    # Goes to reset password link.
    res = testapp.get(url_for('public.reset_password', email=password_reset.user.email,
                              code=password_reset.code))
    # Fills out ResetPasswordForm.
    form = res.forms['resetPasswordForm']
    form['confirm'] = form['password'] = 'superSecret'
    # Submits.
    res = form.submit()
    # Sees error.
    assert escape(_('Reset code "%(code)s" expired at %(isoformat)s', code=password_reset.code,
                    isoformat=password_reset.expires_at.isoformat() + 'Z')) in res


# noinspection PyUnusedLocal
def test_sees_error_message_if_attempting_to_use_reset_code_twice(password_reset, testapp):
    """Show error if reset code has already been used."""
    # Goes to reset password link.
    res = testapp.get(url_for('public.reset_password', email=password_reset.user.email,
                              code=password_reset.code))
    # Fills out ResetPasswordForm.
    form = res.forms['resetPasswordForm']
    form['confirm'] = form['password'] = 'superSecret'
    # Submits.
    res = form.submit().follow()
    assert res.status_code == 200

    # Does the same thing again.
    res = testapp.get(url_for('public.reset_password', email=password_reset.user.email,
                              code=password_reset.code))
    form = res.forms['resetPasswordForm']
    form['confirm'] = form['password'] = 'superSecret'
    res = form.submit()
    # Sees error.
    assert escape(_('Reset code "%(code)s" already used (%(isoformat)s)', code=password_reset.code,
                    isoformat=password_reset.modified_at.isoformat() + 'Z')) in res
