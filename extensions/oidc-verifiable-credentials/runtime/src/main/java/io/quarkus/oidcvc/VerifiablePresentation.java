package io.quarkus.oidcvc;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;

public class VerifiablePresentation {

    private final VerifiableCredential vc;
    private final Set<String> approvedDisclosures;

    public VerifiablePresentation() {
        this(null, Set.of());
    }

    public VerifiablePresentation(VerifiableCredential vc, Set<String> approvedDisclosures) {
        this.vc = vc;
        this.approvedDisclosures = approvedDisclosures;
    }

    public String getVerifiablePresentationString() {
        if (approvedDisclosures.isEmpty()) {
            return addKeyBinding(vc.getSdJwt(), vc.getCredentialJwt());
        }
        SDJWT sdJwt = SDJWT.parse(vc.getSdJwt());

        List<Disclosure> approved = new ArrayList<>();

        for (Disclosure d : sdJwt.getDisclosures()) {
            if (approvedDisclosures.contains(d.getClaimName())) {
                approved.add(d);
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append(sdJwt.getCredentialJwt()).append('~');
        for (Disclosure d : approved) {
            sb.append(d.toString()).append('~');
        }
        return addKeyBinding(sb.toString(), vc.getCredentialJwt());
    }

    private String addKeyBinding(String sdJwt, String credentialJwt) {
        // IF a verifier needs a key binding
        // PrivateKey privateKey = vc.getKeyBindingPrivateKey();
        // SD JWT spec section 4.3: calculate, typically, SHA256 hash over sdJwt presentation, set it as `sd_hash` claim, sign
        // and append to sdJwt without a trailing `~`

        return sdJwt;
    }
}
