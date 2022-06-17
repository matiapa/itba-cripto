import org.apache.commons.lang3.ArrayUtils;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class Steganography {

    static String FILES_DIR = "tmp/";

    public static void embed(File hostFile, File payloadFile, String outFileName, EncodeMode encodeMode) throws IOException {
        if (!hostFile.getName().split("\\.")[1].equals("bmp"))
            throw new RuntimeException("Host file must be a BMP");

        int n = encodeMode== EncodeMode.LSB1 || encodeMode== EncodeMode.LSBI ? 1 : 4;

        // Check that host file is big enough

        String extensionName = payloadFile.getName().split("\\.")[1];
        extensionName = String.format(".%s", extensionName);

        int minSize = (int) (4 + payloadFile.length() + extensionName.length() + 1);
        minSize *= Math.floorDiv(8, n);
        minSize += encodeMode == EncodeMode.LSBI ? 4 : 0;

        System.out.println(minSize);
        System.out.println(hostFile.length());

        if(hostFile.length() <  minSize)
            throw new RuntimeException(String.format("Host file must have at least %d bytes", minSize));

        // Read host file

        FileInputStream is = new FileInputStream(hostFile);
        byte[] hostBytes = new byte[(int) hostFile.length()];
        is.read(hostBytes);

        // Get payload metadata

        int payloadSize = (int) payloadFile.length();
        byte[] payloadSizeBytes = ByteBuffer.allocate(4).putInt(payloadSize).array();

        byte[] extensionNameBytes = ArrayUtils.addAll(extensionName.getBytes(), new byte[]{0});

        // Get payload data

        is = new FileInputStream(payloadFile);
        byte[] payloadDataBytes = new byte[payloadSize];
        is.read(payloadDataBytes);

        // Encode payload data with metadata

        byte[] extendedPayload = ArrayUtils.addAll(payloadSizeBytes, payloadDataBytes);
        extendedPayload = ArrayUtils.addAll(extendedPayload, extensionNameBytes);

        byte[] hostBytesOriginal = hostBytes.clone();
        LSBEncode(extendedPayload, hostBytes, n, encodeMode==EncodeMode.LSBI ? 4 : 0);

        if(encodeMode == EncodeMode.LSBI)
            LSBIApply(hostBytesOriginal, hostBytes);

        // Write tampered host bytes

        FileOutputStream os = new FileOutputStream(FILES_DIR.concat(outFileName));
        os.write(hostBytes);
    }

    public static void extract(File hostFile, String outFileName, EncodeMode encodeMode) throws IOException {
        if (!hostFile.getName().split("\\.")[1].equals("bmp"))
            throw new RuntimeException("Host file must be a BMP");

        int n = encodeMode== EncodeMode.LSB1 || encodeMode== EncodeMode.LSBI ? 1 : 4;

        // Read host file

        FileInputStream is = new FileInputStream(hostFile);
        byte[] hostBytes = new byte[(int) hostFile.length()];
        is.read(hostBytes);

        // Decode payload data with metadata

        if(encodeMode == EncodeMode.LSBI)
            LSBIUnapply(hostBytes);

        int offset = encodeMode==EncodeMode.LSBI ? 4 : 0;
        byte[] payloadBytes = new byte[(int) Math.ceil((hostFile.length() - offset) / (8.0 / n))];
        LSBDecode(hostBytes, payloadBytes, n, offset);

        // Get payload metadata

        int payloadSize = ByteBuffer.wrap(payloadBytes, 0, 4).getInt();

        List<Byte> extensionNameBytes = new ArrayList<>();
        for(int i=4+payloadSize; payloadBytes[i] != 0; i++)
            extensionNameBytes.add(payloadBytes[i]);
        String extensionName = new String(ArrayUtils.toPrimitive(extensionNameBytes.toArray(new Byte[0])), StandardCharsets.UTF_8);

        // Write payload data into output file

        String filename = String.format("%s%s%s", FILES_DIR, outFileName, extensionName);
        File outputFile = new File(filename);
        FileOutputStream os = new FileOutputStream(outputFile);

        os.write(payloadBytes, 4, payloadSize);
    }


    static void LSBEncode(byte[] payload, byte[] host, int n, int hostOffset) {
        int payloadBit=0, hostBit=8-n + hostOffset*8;
        while(payloadBit < payload.length * 8) {
            for(int i=hostBit; i<hostBit+n; i++)
                copyBit(payload, payloadBit++, host, i);
            hostBit += 8;
        }
    }


    static void LSBDecode(byte[] host, byte[] payload, int n, int hostOffset) {
        int payloadBit=0, hostBit=8-n + hostOffset*8;
        while(payloadBit < payload.length * 8) {
            for(int i=hostBit; i<hostBit+n; i++)
                copyBit(host, i, payload, payloadBit++);
            hostBit += 8;
        }
    }


    static void LSBIApply(byte[] original_host, byte[] tampered_host) {
        int[] changes = new int[4];
        int[] conservations = new int[4];

        // Count the amount of changes and conservations for each 2-bit group

        for(int i=4; i<original_host.length; i++) {
            int group = (original_host[i] & 0b00000110) >> 1;

            if(original_host[i] != tampered_host[i])
                changes[group] += 1;
            else
                conservations[group] += 1;
        }

        // Flip the LSB of the 2-bit groups with more changes than conservations

        boolean[] flipped_groups = new boolean[]{false, false, false, false};

        for(int i=4; i<original_host.length; i++) {
            int group = (original_host[i] & 0b00000110) >> 1;

            if(changes[group] > conservations[group]) {
                flipped_groups[group] = true;
                if((tampered_host[i] & 1) == 1)
                    tampered_host[i] &= 0b11111110;
                else
                    tampered_host[i] |= 0b00000001;
            }
        }

        // Create and return the flip byte

        for(int i=0; i<4; i++)
            if(flipped_groups[i])
                tampered_host[i] |= 1;
    }


    static void LSBIUnapply(byte[] host) {
        boolean[] flipped_groups = new boolean[]{false, false, false, false};

        // Recover flipped groups information

        for(int i=0; i<4; i++)
            if((host[i] & 1) == 1)
                flipped_groups[i] = true;

        // Restore the flipped groups

        for(int i=4; i<host.length; i++) {
            int group = (host[i] & 0b00000110) >> 1;

            if(flipped_groups[group]) {
                if((host[i] & 1) == 1)
                    host[i] &= 0b11111110;
                else
                    host[i] |= 0b00000001;
            }
        }
    }


    static void copyBit(byte[] src, int srcBitN, byte[] target, int targetBitN) {
        int mask = 1 << (7 - srcBitN % 8);
        int bit = (src[srcBitN / 8] & mask) >> (7 - srcBitN % 8);

        if(bit == 1)
            target[targetBitN / 8] |= 1 << (7 - targetBitN % 8);
        else
            target[targetBitN / 8] &= ~(1 << (7 - targetBitN % 8));
    }


    public static void main(String[] args) throws IOException {
        File hostFile = new File(FILES_DIR.concat("host.bmp"));
        File payloadFile = new File(FILES_DIR.concat("payload.bin"));
        embed(hostFile, payloadFile, "host_tampered.bmp", EncodeMode.LSBI);

        // TODO: Mostrar error si el tamanio del host es insuficiente
        // TODO: Mostrar error si el host posee compresion
        // TODO: Agregar parsing de argumentos y valores default

        File hostTamperedFile = new File(FILES_DIR.concat("host_tampered.bmp"));
        extract(hostTamperedFile, "payload_recovered", EncodeMode.LSBI);
    }

    // HT: FF x31 FF  FF x8 FF FF FF FF
    // PL: 0  x31 1   0  x8 0  0  1  0
    // OT: FE x31 FF  FE x8 FE FE FF FE

    // 110 -> 111 F
    // 111 -> 110 E

    public enum EncodeMode {LSB1, LSB4, LSBI}

}
