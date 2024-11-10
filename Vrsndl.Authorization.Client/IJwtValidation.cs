namespace Vrsndl.Authorization.Client;

internal interface IJwtValidation
{
    TokenValidationParameters GetValidationParameters();
}
