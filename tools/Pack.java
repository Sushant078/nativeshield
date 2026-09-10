import lab.shield.Envelope;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/** Local synthetic-fixture packer. Never accepts an APK signing key. */
public final class Pack {
    public static void main(String[] args) throws Exception {
        Path build = Paths.get(args[0]);
        byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
        String factory = args.length > 1 ? args[1] : "lab.payload.OriginalFactory";
        if (!factory.matches("[A-Za-z0-9_.$]+")) throw new IllegalArgumentException("factory name");
        String[] dexPaths = args.length > 2 ? java.util.Arrays.copyOfRange(args, 2, args.length)
                : new String[]{"payload-dex/classes.dex", "secondary-dex/classes.dex"};
        StringBuilder source = new StringBuilder("package lab.shield; public final class BuildSecrets { public static final String ORIGINAL_FACTORY=\"" + factory + "\"; public static final int DEX_COUNT=" + dexPaths.length + "; public static byte[] key(){ return new byte[]{");
        for (int i = 0; i < key.length; i++) source.append(i == 0 ? "" : ",").append(key[i]);
        source.append("}; }}");
        Path generated = build.resolve("generated/lab/shield/BuildSecrets.java");
        Files.createDirectories(generated.getParent());
        Files.write(generated, source.toString().getBytes(StandardCharsets.UTF_8));
        String[] identities = new String[dexPaths.length + 1];
        String[] paths = new String[dexPaths.length + 1];
        for (int i=0; i<dexPaths.length; i++) { identities[i]="dex/" + i; paths[i]=dexPaths[i]; }
        identities[dexPaths.length]="resources";
        paths[dexPaths.length]="payload-res.apk";
        for (int i=0; i<paths.length; i++) {
            Path dest = build.resolve("encrypted/shield/" + identities[i] + ".bin");
            Files.createDirectories(dest.getParent());
            Files.write(dest, Envelope.encrypt(Files.readAllBytes(build.resolve(paths[i])), key, identities[i]));
        }
        // Verify authentication rejects ciphertext corruption and entry substitution.
        byte[] sample = Envelope.encrypt(new byte[]{1,2,3}, key, "test");
        boolean wrongIdentity = false, corrupt = false;
        try { Envelope.decrypt(sample, key, "other"); } catch (javax.crypto.AEADBadTagException e) { wrongIdentity=true; }
        sample[sample.length-1] ^= 1;
        try { Envelope.decrypt(sample, key, "test"); } catch (javax.crypto.AEADBadTagException e) { corrupt=true; }
        if (!wrongIdentity || !corrupt) throw new AssertionError("authentication regression");
        System.out.println("PASS envelope authentication and entry binding");
    }
}
