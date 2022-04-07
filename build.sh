rm -rf SSO-Auth/bin
docker run --rm -v /blyatflix/home/SSO/jellyfin-plugin-sso:/app -w /app mcr.microsoft.com/dotnet/sdk:6.0 dotnet publish .
rm -rf /blyatflix/apps/jellyfin/config/data/plugins/sso
docker restart jellyfin
mkdir /blyatflix/apps/jellyfin/config/data/plugins/sso
cp SSO-Auth/bin/Debug/net6.0/publish/SSO-Auth.dll /blyatflix/apps/jellyfin/config/data/plugins/sso/
cp SSO-Auth/bin/Debug/net6.0/publish/IdentityModel.dll /blyatflix/apps/jellyfin/config/data/plugins/sso/
cp SSO-Auth/bin/Debug/net6.0/publish/IdentityModel.OidcClient.dll /blyatflix/apps/jellyfin/config/data/plugins/sso/
chown -R 1000:1000 /blyatflix/apps/jellyfin/config/data/plugins/sso
docker restart jellyfin
