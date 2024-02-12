// -----------------------------------------------------------------------
// <copyright file="EntraIdValidationHelper.cs" company="Microsoft Corporation">
//     Copyright (c) Microsoft Corporation. Licensed under the MIT License.
// </copyright>
// -----------------------------------------------------------------------

namespace Microsoft.WinGet.RestSource.Functions.Common
{
    using System;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using JWT;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Primitives;
    using Microsoft.WinGet.RestSource.Utils.Constants;
    using Microsoft.WinGet.RestSource.Utils.Exceptions;
    using Microsoft.WinGet.RestSource.Utils.Models.Errors;

    /// <summary>
    /// Provides common Entra Id validation helpers.
    /// </summary>
    public static class EntraIdValidationHelper
    {
        /// <summary>
        /// This will check for a valid Entra Id token.
        /// </summary>
        /// <param name="req">the httprequest to process.</param>
        /// <param name="log">Log output.</param>
        public static void ValidateAuthentication(HttpRequest req, ILogger log)
        {
            if (ApiConstants.EntraIdAuthenticationRequired)
            {
                StringValues authorizationHeader;
                bool isAuthHeaderPresent = req.Headers.TryGetValue(HeaderConstants.Authorization, out authorizationHeader);

                if (!isAuthHeaderPresent || StringValues.IsNullOrEmpty(authorizationHeader))
                {
                    throw new ForbiddenException(
                        new InternalRestError(
                            ErrorConstants.ForbiddenErrorCode,
                            string.Format(ErrorConstants.ForbiddenErrorMessage, ApiConstants.CertificateAuthenticationSubjectName)));
                }
            }
        }
    }
}
