package com.example.telia;

import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;

public class TeliaOIDCIdentityProviderFactory extends OIDCIdentityProviderFactory {
    public static final String PROVIDER_ID = "telia-oidc";

    @Override
    public OIDCIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new TeliaOIDCIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }

    @Override
    public String getName() {
        return "Telia OIDC";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
