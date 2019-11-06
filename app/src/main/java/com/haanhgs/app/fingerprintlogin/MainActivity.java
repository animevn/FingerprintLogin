package com.haanhgs.app.fingerprintlogin;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private static final String KEY_NAME = "yourKey";
    private Cipher cipher;
    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private TextView textView;
    private FingerprintManager.CryptoObject cryptoObject;
    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;

    private void initViews(){
        textView = findViewById(R.id.tvMain);
        keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
    }

    private void checkPermission(){
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT)
                != PackageManager.PERMISSION_GRANTED) {
            textView.setText(R.string.add_perm);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void checkIfDeviceHasFingerprintSensor(){
        //check if device have a fingerprint
        if (fingerprintManager != null && !fingerprintManager.isHardwareDetected()) {
            textView.setText(R.string.do_not_have);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void checkIfUserRegisterAFingerprint(){
        //Check that the user has registered at least one fingerprint
        if (fingerprintManager != null && !fingerprintManager.hasEnrolledFingerprints()) {
            textView.setText(R.string.no_fingerprint);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void generateKey(){
        try {
            // Obtain a reference to the Keystore using the standard Android keystore container
            // identifier (“AndroidKeystore”)//
            keyStore = KeyStore.getInstance("AndroidKeyStore");

            //Generate the key//
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            //Initialize an empty KeyStore//
            keyStore.load(null);

            //Initialize the KeyGenerator//
            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    //Configure this key so that the user has to confirm their identity with a
                    // fingerprint each time they want to use it//
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());

            //Generate the key//
            keyGenerator.generateKey();

        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | InvalidAlgorithmParameterException
                | CertificateException
                | IOException exc) {
            exc.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    public boolean initCipher() {
        try {
            //Obtain a cipher instance and configure it with the properties
            // required for fingerprint authentication
            cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME, null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            //Return true if the cipher has been initialized successfully//
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {

            //Return false if cipher initialization failed//
            return false;
        } catch (KeyStoreException | CertificateException
                | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    private void checkFingerprint(){
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
            fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
            checkIfDeviceHasFingerprintSensor();
            checkIfUserRegisterAFingerprint();
            checkPermission();

            if (!keyguardManager.isKeyguardSecure()) {
                textView.setText(R.string.enable_keyguard);
            }else {
                try{
                    generateKey();
                }catch (Exception e){
                    e.printStackTrace();
                }

                if (initCipher()) {
                    //If the cipher is initialized successfully, then create a CryptoObject instance//
                    cryptoObject = new FingerprintManager.CryptoObject(cipher);

                    // Here, I’m referencing the FingerprintHandler class that we’ll create
                    // in the next section. This class will be responsible
                    // for starting the authentication process (via the startAuth method)
                    // and processing the authentication process events//
                    FingerprintHandler helper = new FingerprintHandler(this);
                    helper.startAuth(fingerprintManager, cryptoObject);
                }
            }
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initViews();
        checkFingerprint();

    }
}
