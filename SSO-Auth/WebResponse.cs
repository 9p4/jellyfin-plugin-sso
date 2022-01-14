namespace Jellyfin.Plugin.SSO_Auth
{
  class WebResponse {
    public static string BuildResponse(string accessToken) {
      return @"<!DOCTYPE html>
<script src='/web/main.jellyfin.bundle.js'></script>
<script>
</script>" + accessToken;
    }
  }
}
