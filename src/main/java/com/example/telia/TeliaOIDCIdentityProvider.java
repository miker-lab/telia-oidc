package com.example.telia;

import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.broker.provider.IdentityBrokerException;
import com.example.telia.util.JwtRequestObjectBuilder;

import jakarta.ws.rs.core.UriBuilder;

public class TeliaOIDCIdentityProvider extends OIDCIdentityProvider {

    public TeliaOIDCIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
    }

@Override
protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    try {
        String jwt = JwtRequestObjectBuilder.buildSignedRequestObject(
            session,
            session.getContext().getRealm(),
            getConfig().getClientId(),
            request.getRedirectUri(),
            "http://ftn.ficora.fi/2017/loa2",
            "https://tunnistus.telia.fi/uas"
        );
        return UriBuilder.fromUri(getConfig().getAuthorizationUrl()).queryParam("request", jwt);
    } catch (Exception e) {
        throw new IdentityBrokerException("Failed to create request object", e);
    }
}
}
