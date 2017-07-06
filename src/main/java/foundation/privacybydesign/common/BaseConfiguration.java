package foundation.privacybydesign.common;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Base class for *Configuration classes in issuer servlets.
 *
 * See BIGConfiguration in irma_big_server for an example.
 * Mostly what you have to do is to inherit this class and create a
 * getInstance() method:
 *
 *     if (instance == null) {
 *         try {
 *             String json = new String(getResource(CONFIG_FILENAME));
 *             instance = GsonUtil.getGson().fromJson(json, MyConfiguration.class);
 *         } catch (IOException e) {
 *             System.out.println("could not load configuration");
 *             instance = new MyConfiguration();
 *         }
 *     }
 *     return instance;
 *
 * Other than that, just add private members with getters which you can use
 * directly in a config.json file in the resources folder (usually
 * build/resources/main/config.json).
 */
public class BaseConfiguration {
    // Fields in the config.json file
    private String private_key_path = "";

    private PrivateKey privateKey = null;

    // TODO: add something like a getInstance() here (not sure how to do
    // that, static methods cannot be overriden in Java).

    /**
     * Load a resource from build/resources/main and return a byte[] buffer.
     *
     * @param filename file to load
     * @return the whole file as a byte[] buffer
     * @throws IOException
     */
    public static byte[] getResource(String filename) throws IOException {
        URL url = BaseConfiguration.class.getClassLoader().getResource(filename);
        if (url == null)
            throw new IOException("Could not load file " + filename);

        URLConnection urlCon = url.openConnection();
        urlCon.setUseCaches(false);
        return convertSteamToByteArray(urlCon.getInputStream(), 2048);
    }

    public static byte[] convertSteamToByteArray(InputStream stream, int size) throws IOException {
        byte[] buffer = new byte[size];
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        int line;
        while ((line = stream.read(buffer)) != -1) {
            os.write(buffer, 0, line);
        }
        stream.close();

        os.flush();
        os.close();
        return os.toByteArray();
    }

    /**
     * Get (and possibly load) the private key that's set in private_key_path
     * of the configuration file.
     *
     * @return private key
     * @throws KeyManagementException
     */
    public PrivateKey getPrivateKey() throws KeyManagementException {
        if (privateKey == null) {
            privateKey = loadPrivateKey(private_key_path);
        }
        return privateKey;
    }

    private PrivateKey loadPrivateKey(String filename) throws KeyManagementException {
        try {
            return decodePrivateKey(BaseConfiguration.getResource(filename));
        } catch (IOException e) {
            throw new KeyManagementException(e);
        }
    }

    private PrivateKey decodePrivateKey(byte[] rawKey) throws KeyManagementException {
        try {
            if (rawKey == null || rawKey.length == 0)
                throw new KeyManagementException("Could not read private key");

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(rawKey);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (NoSuchAlgorithmException |InvalidKeySpecException e) {
            throw new KeyManagementException(e);
        }
    }

    /**
     * Load a public key from a path (@filename).
     * Should be used in a getPublicKey function that only loads the key on
     * first use.
     *
     * @param filename the path to the private key (relative to
     *                 build/resources/main).
     * @return public key
     * @throws KeyManagementException
     */
    public PublicKey loadPublicKey(String filename) throws
            KeyManagementException {
        try {
            return decodePublicKey(BaseConfiguration.getResource(filename));
        } catch (IOException e) {
            throw new KeyManagementException(e);
        }
    }

    private PublicKey decodePublicKey(byte[] rawKey) throws KeyManagementException {
        try {
            if (rawKey == null || rawKey.length == 0)
                throw new KeyManagementException("Could not read public key");

            X509EncodedKeySpec spec = new X509EncodedKeySpec(rawKey);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
            throw new KeyManagementException(e);
        }
    }
}
