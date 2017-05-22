import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import EncryptionUtil.*;

public class Message{
    private int number_of_sender = 0;
    private byte [] message;
    private byte [] signatures;
    private String summary;

    public KeyPair generate() throws Exception{
        return EncryptionUtil.generate();
    }

    public void encrypt(String content,PublicKey key) throws Exception{
        message = EncryptionUtil.encrypt(content,key);
        summary = EncryptionUtil.summary(content);
    }

    public String decrypt(PrivateKey key) throws Exception{
        return EncryptionUtil.decrypt(message,key);
    }

    public String summary() throws Exception{
        return summary;
    }

    public void sign(PrivateKey key){

    }

}
