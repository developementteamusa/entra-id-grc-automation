"""Interactive delegated authentication; access tokens are never persisted."""
import os

SCOPES = ["User.Read.All", "GroupMember.Read.All"]


def get_access_token():
    tenant_id = os.getenv("AZURE_TENANT_ID", "").strip()
    client_id = os.getenv("AZURE_CLIENT_ID", "").strip()
    if not tenant_id or not client_id:
        raise ValueError("Set AZURE_TENANT_ID and AZURE_CLIENT_ID before running --live")

    # Delay import so offline demo does not require Microsoft login packages.
    import msal
    app = msal.PublicClientApplication(
        client_id=client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise RuntimeError(f"Device code flow initialization failed: {flow.get('error', 'unknown error')}")
    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(f"Sign-in failed: {result.get('error_description', 'unknown error')}")
    return result["access_token"], tenant_id
