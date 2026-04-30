import pytest
import requests

def test_login(): pass
def test_login_incorrect(): pass
def test_login_malformed(): pass

def test_register(): pass
def test_register_username_exists(): pass
def test_register_token_invalid(): pass
def test_register_role_invalid(): pass
def test_register_malformed(): pass

def test_revoke(): pass
def test_revoke_token_invalid(): pass

def test_revoke_all(): pass
def test_revoke_all_token_invalid(): pass

def test_change_username(): pass
def test_change_username_token_invalid(): pass
def test_change_username_role_invalid(): pass

def test_change_password(): pass
def test_change_password_token_invalid(): pass

def test_get_role(): pass
def test_get_role_token_invalid(): pass

def test_change_role(): pass
def test_change_role_token_invalid(): pass
def test_change_role_role_invalid(): pass