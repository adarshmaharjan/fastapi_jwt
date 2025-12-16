from fastapi.security import OAuth2PasswordBearer

reusable_auth = OAuth2PasswordBearer(
    tokenUrl="/login",
    scheme_name="JWT",
)



