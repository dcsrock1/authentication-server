invalid_token_response = """
log_event("invalid_token", "warning")
return {"info": "Invalid or expired token"}, 401
"""

invalid_authorization_response = """
log_event("authorization_error", "warning", {"user_id": user_id, "target": data["target"], "role": data["role"], "details": "User does not have correct permission level"})
return {"info": "Not authorized"}, 403
"""