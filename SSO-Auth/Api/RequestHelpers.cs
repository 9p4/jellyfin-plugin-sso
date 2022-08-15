// The following code is a derivative work of the code from the Jellyfin project,
// which is licensed GPLv2. This code therefore is also licensed under the terms
// of the GNU Public License, verison 2.
// https://github.com/jellyfin/jellyfin/blob/a60cb280a3d31ba19ffb3a94cf83ef300a7473b7/Jellyfin.Api/Helpers/RequestHelpers.cs#L63-L77

// Use of this relatively small snippet complies with fair use
// See https://www.gnu.org/licenses/gpl-faq.en.html#SourceCodeInDocumentation
// These helpers were not published within a Nuget package, so it was neccessary to re-implement.

using System;
using System.Threading.Tasks;
using Jellyfin.Data.Enums;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.SSO_Auth.Helpers;

/// <summary>
/// Request Extensions.
/// </summary>
public static class RequestHelpers
{
    /// <summary>
    /// Checks if the user can update an entry.
    /// </summary>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="requestContext">The <see cref="HttpRequest"/>.</param>
    /// <param name="userId">The user id.</param>
    /// <param name="restrictUserPreferences">Whether to restrict the user preferences.</param>
    /// <returns>A <see cref="bool"/> whether the user can update the entry.</returns>
    internal static async Task<bool> AssertCanUpdateUser(IAuthorizationContext authContext, HttpRequest requestContext, Guid userId, bool restrictUserPreferences)
    {
        var auth = await authContext.GetAuthorizationInfo(requestContext).ConfigureAwait(false);

        var authenticatedUser = auth.User;

        // If they're going to update the record of another user, they must be an administrator
        if ((!userId.Equals(auth.UserId) && !authenticatedUser.HasPermission(PermissionKind.IsAdministrator))
            || (restrictUserPreferences && !authenticatedUser.EnableUserPreferenceAccess))
        {
            return false;
        }

        return true;
    }
}
