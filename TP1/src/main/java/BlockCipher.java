import java.util.Arrays;

public class BlockCipher {
    private static final int BLOCKSIZE_128=128;
    private static final int BLOCKSIZE_8=8;

    private static final int BLOCKSIZE_TBD=0;//TODO no se que tamanio usa CBC


    public static byte[] ECBEncrypt(byte[] input){
        int size=input.length;
        int outputSize=0;
        if (size%BLOCKSIZE_128!=0){
            outputSize=(size/BLOCKSIZE_128+1)*BLOCKSIZE_128; //pad out to fill blocksize
        }
        else
            outputSize=size;
        byte[] inputFixedSize=new byte[outputSize];
        System.arraycopy(input,0,inputFixedSize,0,input.length);
        byte[] output=new byte[outputSize];
        for (int i = 0; i <outputSize/BLOCKSIZE_128 ; i++) {

            byte[] aux=encrypt(Arrays.copyOfRange(inputFixedSize, i*BLOCKSIZE_128, (i+1)*BLOCKSIZE_128));
            System.arraycopy(aux,0,output,i*BLOCKSIZE_128,BLOCKSIZE_128);

        }
        return output;

    }
    public static byte[] ECBDecrypt(byte[] input){
        byte[] output=new byte[input.length];
        for (int i = 0; i <input.length/BLOCKSIZE_128 ; i++) {

            byte[] aux=decrypt(Arrays.copyOfRange(input, i*BLOCKSIZE_128, (i+1)*BLOCKSIZE_128));
            System.arraycopy(aux,0,output,i*BLOCKSIZE_128,BLOCKSIZE_128);

        }
        return output;

    }

    public static byte[] CFBEncrypt(byte[]input, byte[]IV){
        int size=input.length;
        int outputSize=0;
        if (size%BLOCKSIZE_8!=0){
            outputSize=(size/BLOCKSIZE_8+1)*BLOCKSIZE_8; //pad out to fill blocksize
        }
        else
            outputSize=size;
        byte[] inputFixedSize=new byte[outputSize];
        System.arraycopy(input,0,inputFixedSize,0,input.length);
        byte[] output=new byte[outputSize];
        for (int i = 0; i < outputSize/BLOCKSIZE_8; i++) {

            IV=encrypt(IV);
            for (int j = i*BLOCKSIZE_8; j <i*BLOCKSIZE_8+8 ; j++) {
                output[j]=(byte)(input[j]^IV[j%BLOCKSIZE_8]);
                IV[j%BLOCKSIZE_8]=output[j];
            }
        }
        return output;
    }
    public static byte[] CFBDecrypt(byte[]input, byte[]IV){
        int size=input.length;
        int outputSize=0;
        if (size%BLOCKSIZE_8!=0){
            outputSize=(size/BLOCKSIZE_8+1)*BLOCKSIZE_8; //pad out to fill blocksize
        }
        else
            outputSize=size;
        byte[] inputFixedSize=new byte[outputSize];
        System.arraycopy(input,0,inputFixedSize,0,input.length);
        byte[] output=new byte[outputSize];
        for (int i = 0; i < outputSize/BLOCKSIZE_8; i++) {

            IV=encrypt(IV);
            for (int j = i*BLOCKSIZE_8; j <i*BLOCKSIZE_8+8 ; j++) {
                output[j]=(byte)(input[j]^IV[j%BLOCKSIZE_8]);
                IV[j%BLOCKSIZE_8]=input[j];
            }
        }
        return output;
    }
    public static byte[] OFBEncrypt(byte[]input, byte[]IV){
        int size=input.length;
        int outputSize=0;
        if (size%BLOCKSIZE_128!=0){
            outputSize=(size/BLOCKSIZE_128+1)*BLOCKSIZE_128; //pad out to fill blocksize
        }
        else
            outputSize=size;
        byte[] inputFixedSize=new byte[outputSize];
        System.arraycopy(input,0,inputFixedSize,0,input.length);
        byte[] output=new byte[outputSize];
        for (int i = 0; i < outputSize/BLOCKSIZE_128; i++) {

            IV=encrypt(IV);
            for (int j = i*BLOCKSIZE_128; j <i*BLOCKSIZE_128+8 ; j++) {
                output[j]=(byte)(input[j]^IV[j%BLOCKSIZE_128]);
            }
        }
        return output;
    }
    public static byte[] OFBDecrypt(byte[]input, byte[]IV){
        return OFBEncrypt(input,IV);
    }
    public static byte[] CBCEncrypt(byte[]input, byte[]IV){
        int size=input.length;
        int outputSize=0;
        if (size%BLOCKSIZE_TBD!=0){
            outputSize=(size/BLOCKSIZE_TBD+1)*BLOCKSIZE_TBD; //pad out to fill blocksize
        }
        else
            outputSize=size;
        byte[] inputFixedSize=new byte[outputSize];
        System.arraycopy(input,0,inputFixedSize,0,input.length);
        byte[] output=new byte[outputSize];
        byte[]aux=new byte[BLOCKSIZE_TBD];
        for (int i = 0; i < outputSize/BLOCKSIZE_TBD; i++) {
            for (int j = 0; j <i*BLOCKSIZE_TBD ; j++) {
                aux[j]=(byte)(input[i*BLOCKSIZE_TBD+j]^IV[j]);
            }
            aux=encrypt(aux);
            System.arraycopy(aux,0,output,i*BLOCKSIZE_TBD,BLOCKSIZE_TBD);
        }
        return output;
    }
    public static byte[] CBCDecrypt(byte[]input, byte[]IV){
//        TODO
    }

}
