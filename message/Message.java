package message;

import java.util.*;
import javax.crypto.*;
import java.security.*;
import message.encryptionutil.*;

public class Message{
    private int number_of_signature = 0;
    private String message;
    private List <String> signature;
    private String summary;

    public Message(){
        signature = new ArrayList<String>();
    }

    public Message(String msg) throws Exception{
        signature = new ArrayList<String>();
        Scanner sc = new Scanner(msg);
        // Parse the summary
        sc.useDelimiter("");
        byte summary_length = (byte)(sc.next().charAt(0));
        summary = "";
        for(int i = 0; i < summary_length; i++){
            summary = summary + sc.next().charAt(0);
        }
        sc.useDelimiter(" ");

        //Parse the signatures
        number_of_signature = sc.nextInt();
        sc.useDelimiter("");
        sc.next();
        for(int j = 0; j < number_of_signature; j++){
            String sign = "";
            for(int i = 0; i < 256; i++){
                char c = sc.next().charAt(0);
                sign = sign + c;
            }
            signature.add(sign);
        }

        // Parse the cypher text.
        message = "";
        while(sc.hasNext()){
            message = message + sc.next();
        }

    }

    public String toString(){
        String result = (char)((byte)summary.length()) + summary + " ";
        result = result + number_of_signature + " ";
        for(String sign:signature){
            result = result + sign;
        }
        return result + message;
    }

    public KeyPair Generate() throws Exception{
        return EncryptionUtil.generate();
    }

    public void Encrypt(String content,PublicKey key) throws Exception{
        message = EncryptionUtil.encrypt(content,key);
        summary = EncryptionUtil.summary(content);
    }

    public String Decrypt(PrivateKey key) throws Exception{
        return EncryptionUtil.decrypt(message,key);
    }

    public String Summary() throws Exception{
        return summary;
    }

    public void Sign(PrivateKey key) throws Exception{
        signature.add(EncryptionUtil.sign(message,key));
        number_of_signature = number_of_signature + 1;
    }

    public boolean Validate(PublicKey key) throws Exception{
        for(String sign: signature){
            if(EncryptionUtil.verify(message,key,sign)) return true;
        }
        return false;
    }
}
