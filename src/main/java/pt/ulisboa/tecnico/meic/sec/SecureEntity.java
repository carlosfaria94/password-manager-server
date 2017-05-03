package pt.ulisboa.tecnico.meic.sec;

public abstract class SecureEntity {
    String publicKey;
    String nonce;
    String timestamp;
    String reqSignature;

    public abstract String[] getInsertFields();
    public abstract String[] getRetrieveFields();
    public abstract String[] getFieldsReadyToSend();
}
