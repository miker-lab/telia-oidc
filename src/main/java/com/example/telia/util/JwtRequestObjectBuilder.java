package com.example.telia.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.*;
import org.keycloak.models.*;
import org.keycloak.keys.*;

import java.security.interfaces.RSAPrivateKey;
import java.util.*;

import org.keycloak.models.KeyManager;
//import org.keycloak.keys.KeyWrapper;
import org.keycloak.crypto.KeyUse;

public class JwtRequestObjectBuilder {
    public static String buildSignedRequestObject(
            KeycloakSession session,
            RealmModel realm,
            String clientId,
            String redirectUri,
            String acrValues,
            String audience) {
        try {
            RSAPrivateKey privateKey = (RSAPrivateKey) session.keys()
                .getActiveKey(realm, KeyUse.SIG, "RS256")
                .getPrivateKey();
            //RSAPrivateKey privateKey = (RSAPrivateKey) session.keys().getActiveKey(realm, KeyManager.ActiveRsaKey.class).getPrivateKey();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience(audience)
                    .claim("response_type", "code")
                    .claim("scope", "openid")
                    .claim("client_id", clientId)
                    .claim("redirect_uri", redirectUri)
                    .claim("acr_values", acrValues)
                    .claim("nonce", UUID.randomUUID().toString())
                    .claim("state", UUID.randomUUID().toString())
                    .jwtID(UUID.randomUUID().toString())
                    .expirationTime(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                    claims);
            signedJWT.sign(new RSASSASigner(privateKey));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Error building signed request object", e);
        }
    }
}
