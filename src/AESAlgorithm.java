import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class AESAlgorithm {

    // 학번과 이름을 이진수로 변환하여 AES 키 생성
    public static SecretKey generateKey(String studentId, String name) {
        // 학번 10문자 + 이름 6문자 = 16문자
        String studentIdBinary = stringToBinary(studentId); // 학번을 이진수로 변환
        String nameBinary = stringToBinary(name);           // 이름을 이진수로 변환

        // 128비트(16바이트) AES 키 만들기
        String keyBinary = (studentIdBinary + nameBinary).substring(0, 128); // 128비트로 자름
        byte[] keyBytes = new byte[16]; // 128비트 = 16바이트
        for (int i = 0; i < 16; i++) {
            keyBytes[i] = (byte) Integer.parseInt(keyBinary.substring(i * 8, (i + 1) * 8), 2);
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    // 문자열을 이진수로 변환
    public static String stringToBinary(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            result.append(String.format("%8s", Integer.toBinaryString(c)).replaceAll(" ", "0"));
        }
        return result.toString();
    }

    // AES 암호화
    public static byte[] aesEncrypt(String plaintext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext.getBytes());
    }

    // AES 복호화
    public static String aesDecrypt(byte[] ciphertext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes);
    }

    // IvParameterSpec 생성 (암호화 초기화 벡터)
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Avalanche 효과: 문자열의 첫 번째 비트를 변경
    public static String flipFirstBit(String binaryStr) {
        String flippedBit = binaryStr.charAt(0) == '0' ? "1" : "0";
        return flippedBit + binaryStr.substring(1);
    }

    // 바이트 배열을 이진 문자열로 변환
    public static String bytesToBinary(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return result.toString();
    }

    // 바이트 배열 간의 비트 차이 계산
    public static int calculateBitDifference(byte[] arr1, byte[] arr2) {
        int diffCount = 0;
        for (int i = 0; i < arr1.length; i++) {
            int xorResult = arr1[i] ^ arr2[i]; // XOR 연산으로 비트 차이 찾기
            diffCount += Integer.bitCount(xorResult); // XOR 결과에서 1인 비트 개수를 셈
        }
        return diffCount;
    }

    // 바이트 배열을 16진수로 변환하는 메소드
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b)); // 각 바이트를 16진수 2자리로 변환
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        // 학번과 이름
        String studentId = "2022126061"; // 학번 10문자
        String name = "YANGJW";          // 이름 6문자

        // 평문
        String plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // 1. AES 암호키 생성
        SecretKey key = generateKey(studentId, name);
        System.out.println("AES 암호키 생성 완료");

        // 2. 평문 암호화
        IvParameterSpec iv = generateIv();
        byte[] ciphertext = aesEncrypt(plaintext, key, iv);
        System.out.println("암호화된 텍스트 (바이트 배열): " + Arrays.toString(ciphertext));
        System.out.println("암호화된 텍스트 (16진수): " + bytesToHex(ciphertext));

        // 3. 복호화
        String decryptedText = aesDecrypt(ciphertext, key, iv);
        System.out.println("복호화된 텍스트: " + decryptedText);

        System.out.println("복호화된 텍스트와 plain text가 같은가? " + decryptedText.equals(plaintext));

        // 4. 평문의 2진수 변환 후 첫 번째 비트 변경 후 암호화
        String plaintextBinary = stringToBinary(plaintext);
        String flippedPlaintextBinary = flipFirstBit(plaintextBinary); // 첫 번째 비트 변경
        byte[] flippedPlaintextBytes = new byte[flippedPlaintextBinary.length() / 8];
        for (int i = 0; i < flippedPlaintextBinary.length(); i += 8) {
            flippedPlaintextBytes[i / 8] = (byte) Integer.parseInt(flippedPlaintextBinary.substring(i, i + 8), 2);
        }
        String flippedPlaintext = new String(flippedPlaintextBytes);

        byte[] flippedCiphertext = aesEncrypt(flippedPlaintext, key, iv);
        System.out.println("첫 번째 비트 바꾼 평문 암호화 텍스트 (바이트 배열): " + Arrays.toString(flippedCiphertext));
        System.out.println("첫 번째 비트 바꾼 평문 암호화 텍스트 (16진수): " + bytesToHex(flippedCiphertext));

        // 이전에 AES로 암호화된 결과와 얼마나 많은 비트가 달라지는지 확인
        int plaintextBitDiff = calculateBitDifference(ciphertext, flippedCiphertext);
        System.out.println("평문 첫 비트 변경 후 암호화된 텍스트 간 비트 차이: " + plaintextBitDiff + " 비트");

        // 5. 암호키의 첫 번째 비트 변경 후 암호화
        String keyBinary = bytesToBinary(key.getEncoded());
        String flippedKeyBinary = flipFirstBit(keyBinary);
        byte[] flippedKeyBytes = new byte[flippedKeyBinary.length() / 8];
        for (int i = 0; i < flippedKeyBinary.length(); i += 8) {
            flippedKeyBytes[i / 8] = (byte) Integer.parseInt(flippedKeyBinary.substring(i, i + 8), 2);
        }
        SecretKey flippedKey = new SecretKeySpec(flippedKeyBytes, "AES");

        byte[] flippedKeyCiphertext = aesEncrypt(plaintext, flippedKey, iv);
        System.out.println("첫 번째 비트 바꾼 키로 암호화된 텍스트 (바이트 배열): " + Arrays.toString(flippedKeyCiphertext));
        System.out.println("첫 번째 비트 바꾼 키로 암호화된 텍스트 (16진수): " + bytesToHex(flippedKeyCiphertext));

        // 이전에 AES로 암호화된 결과와 얼마나 많은 비트가 달라지는지 확인
        int keyBitDiff = calculateBitDifference(ciphertext, flippedKeyCiphertext);
        System.out.println("암호키 첫 비트 변경 후 암호화된 텍스트 간 비트 차이: " + keyBitDiff + " 비트");
    }
}
