package sha3;

import javacard.framework.*;

/**
 *
 * @author Matej Evin
 * 6th March 2018
 */
 
public class Sha3Core {
    
    //Defines
    public final static byte    SUCCESS             = (byte)    0;
    public final static short   KECCAKF_ROUNDS      = (short)  24;
    public final static short   WORDL               = (short)   8;
    public final static short   STATE_BYTES         = (short) 200;
    public final static short   STATE_SLICE         = (short)  25;
    
    //* this stuff is in big endian!
    public final static byte[] KECCAKF_RNDC = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, // 0x0000000000000001
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x82, // 0x0000000000008082
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x8a, // 0x800000000000808a
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x00, // 0x8000000080008000
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x8b, // 0x000000000000808b
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x01, // 0x0000000080000001
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x81, // 0x8000000080008081
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x09, // 0x8000000000008009
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x8a, // 0x000000000000008a
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x88, // 0x0000000000000088
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x09, // 0x0000000080008009
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x0a, // 0x000000008000000a
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x8b, // 0x000000008000808b
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x8b, // 0x800000000000008b
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x89, // 0x8000000000008089
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x03, // 0x8000000000008003
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x02, // 0x8000000000008002
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, // 0x8000000000000080
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x0a, // 0x000000000000800a
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x0a, // 0x800000008000000a
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x81, // 0x8000000080008081
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x80, // 0x8000000000008080
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x01, // 0x0000000080000001
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x00, (byte) 0x80, (byte) 0x08};// 0x8000000080008008
    
    public final static short[] KECCAKF_ROTC = {
        (byte) 0x01, (byte) 0x03, (byte) 0x06, (byte) 0x0a, (byte) 0x0f, (byte) 0x15, (byte) 0x1c, (byte) 0x24, 
        (byte) 0x2d, (byte) 0x37, (byte) 0x02, (byte) 0x0e, (byte) 0x1b, (byte) 0x29, (byte) 0x38, (byte) 0x08, 
        (byte) 0x19, (byte) 0x2b, (byte) 0x3e, (byte) 0x12, (byte) 0x27, (byte) 0x3d, (byte) 0x14, (byte) 0x2c};
     
    public final static short[] KECCAKF_PILN = {
        (byte) 0x0a, (byte) 0x07, (byte) 0x0b, (byte) 0x11, (byte) 0x12, (byte) 0x03, (byte) 0x05, (byte) 0x10, 
        (byte) 0x08, (byte) 0x15, (byte) 0x18, (byte) 0x04, (byte) 0x0f, (byte) 0x17, (byte) 0x13, (byte) 0x0d, 
        (byte) 0x0c, (byte) 0x02, (byte) 0x14, (byte) 0x0e, (byte) 0x16, (byte) 0x09, (byte) 0x06, (byte) 0x01};
    
    //sha3 context
    //private byte[] b = null;
    private byte[] st = null;   //state
    private short pt;           //??
    private short rsiz;         //resize
    private short mdlen;        //message digest length    
    
    //Constructor
    public Sha3Core() {
        st = JCSystem.makeTransientByteArray(STATE_BYTES, JCSystem.CLEAR_ON_DESELECT);
    }
    
    //swap endianness on state
    private void swapEndian(byte[] arr) {
        short i;
        byte aux;
        for (i = 0; i < STATE_SLICE; i++) {
            aux = arr[(short) (i*WORDL)];
            arr[(short)( i*WORDL)] = arr[(short) (i*WORDL+7)];
            arr[(short) (i*WORDL+7)] = aux;
            aux = arr[(short) (i*WORDL+1)];
            arr[(short) (i*WORDL+1)] = arr[(short) (i*WORDL+6)];
            arr[(short) (i*WORDL+6)] = aux;
            aux = arr[(short) (i*WORDL+2)];
            arr[(short) (i*WORDL+2)] = arr[(short) (i*WORDL+5)];
            arr[(short) (i*WORDL+5)] = aux;
            aux = arr[(short) (i*WORDL+3)];
            arr[(short) (i*WORDL+3)] = arr[(short) (i*WORDL+4)];
            arr[(short) (i*WORDL+4)] = aux;
        }
    }

    //word bit rotation of to the left
    //x has to be array of 8 bytes, result stored in out, x is not modified
    //EXACT index
    private void rotlW(byte[] arr, short startIndex, short shift, byte[] out) { 
        
        asnWords(out, (short) 0, arr, startIndex);
        
        byte carry = 0;
        byte next;
        short i;
        while (shift != (short) 0) {
            shift--;
            //carry = (byte) 0;
            for (i = (short) (WORDL - 1); i >= (short) 0; i--) {
                if ((byte) (out[i] & 0x80) != (byte) 0)
                    next = (byte) 1;
                else
                    next = (byte) 0;
                out[i] = (byte) (carry | (out[i] << 1));
                carry = next;
            }
            out[WORDL-1] |= carry;
            carry = 0;
        }
    }
  
    //bitwise XOR of two words, save in w1
    //REQUIRES EXACT INDEX
    private void xorWords(byte[] w1, short index1, byte[] w2, short index2) {
        short i;
        for (i = 0; i < WORDL; i++)
            w1[(short)(index1+i)] ^= w2[(short)(index2+i)];
    }
    
    //bitwise OR of two words, save in w1
    //REQUIRES EXACT INDEX
    private void orWords(byte[] w1, short index1, byte[] w2, short index2) {
        short i;
        for (i = 0; i < WORDL; i++)
            w1[(short) (index1+i)] |= w2[(short) (index2+i)];
    }
    
    //bitwise AND of two words, save in w1
    //REQUIRES EXACT INDEX
    private void andWords(byte[] w1, short index1, byte[] w2, short index2) {
        short i;
        for (i = 0; i < WORDL; i++)
            w1[(short) (index1+i)] &= w2[(short) (index2+i)];
    }
    
    //Negate a word w2, save it into w1
    //REQUIRES EXACT INDEX
    private void negateWord(byte[] w1, short index1, byte[] w2, short index2) {
        short i;
        for (i = 0; i < WORDL; i++)
            w1[(short) (index1+i)] = (byte) ~w2[(short) (index2+i)];
    }
    
    //assign word w2 into w1
    //index specifies which number in array should be used (array can therefore be the same)
    //REQUIRES EXACT INDEX
    private void asnWords(byte[] w1, short index1, byte[] w2, short index2) {
        short i;
        for (i = 0; i < WORDL; i++)
            w1[(short) (index1+i)] = w2[(short) (index2+i)];
    }
    
    //KECCAK FUNCTION - updating state with 24 rounds
    private void keccakf(byte[] st) {
        //byte[WORDL] is the same as uint64_t
        
        //C [WORDL*5]
        byte[] bc = JCSystem.makeTransientByteArray((short) (WORDL*5), JCSystem.CLEAR_ON_DESELECT);
        //aux variable [WORDL]
        byte[] t = JCSystem.makeTransientByteArray(WORDL, JCSystem.CLEAR_ON_DESELECT);
        //rotl result [WORDL]
        byte[] rotl = JCSystem.makeTransientByteArray(WORDL, JCSystem.CLEAR_ON_DESELECT);
        short i, j, r;      //iterators
    
        //change endianness
        swapEndian(st);
        
        for (r = 0; r < KECCAKF_ROUNDS; r++) {
    
            // Theta function (NIST.FIPS.202 page 20), sha3tiny.c line 50
            for (i = 0; i < 5; i++) {
                //successive XORing into state, then assigning into C
                asnWords(bc, (short) (i*WORDL), st, (short) ( i    *WORDL));
                xorWords(bc, (short) (i*WORDL), st, (short) ((i+5) *WORDL));
                xorWords(bc, (short) (i*WORDL), st, (short) ((i+10)*WORDL));
                xorWords(bc, (short) (i*WORDL), st, (short) ((i+15)*WORDL));
                xorWords(bc, (short) (i*WORDL), st, (short) ((i+20)*WORDL));
            }
            
            for (i = 0; i < 5; i++) {
                //sha3tiny.c line 55
                //check if functions are indexing correctly!
                rotlW(bc, (short) ((short) ((short) (i + 1) % 5) * WORDL), (short) 1, rotl);
                xorWords(rotl, (short) 0, bc, (short) ((short) ((short) (i + 4) % 5) * WORDL));
                asnWords(t, (short) 0, rotl, (short) 0);
                for (j = 0; j < 25; j += 5)
                    xorWords(st, (short) ((short) (i + j) * WORDL), t, (short) 0);
            }
            
            //Rho and Pi functions together (NIST.FIPS.202 page 20-22), sha3tiny line 60
            asnWords(t, (short) 0, st, WORDL);
            for (i = 0; i < 24; i++) {
                j = KECCAKF_PILN[i];
                asnWords(bc, (short) 0, st, (short) (j * WORDL));
                //* TODO ROTL here, save in rotl
                rotlW(t, (short) 0, KECCAKF_ROTC[i], rotl);
                asnWords(st, (short) (j * WORDL), rotl, (short) 0);
                asnWords(t, (short) 0, bc, (short) 0);
            }
            
            //Chi function (NIST.FIPS.202 page 23), sha3tiny line 69
            for (j = 0; j < 25; j+= 5) {
                for (i = 0; i < 5; i++)
                    asnWords(bc, (short) (i * WORDL), st, (short) ((i + j) * WORDL));
                for (i = 0; i < 5; i++) {
                    negateWord(t, (short) 0, bc, (short) ((short) ((short) (i + 1) % 5) * WORDL));
                    andWords(t, (short) 0, bc, (short) ((short) ((short) (i + 2) % 5) * WORDL));
                    xorWords(st, (short) ((j + i) * WORDL), t, (short) 0);
                }
            }
            
            //Iota function (NIST.FIPS.202 page 23), sha3tiny line 77
            xorWords(st, (short) 0, KECCAKF_RNDC, (short) (r * WORDL));
        }
        
        //swap endianness
        swapEndian(st);
    }
    
    //init hash engine
    //len = length of the message digest (in bytes)
    private byte init(short len) {
        
        mdlen = len;
        rsiz = (short) (200 - 2 * mdlen);
        pt = 0;
        
        return SUCCESS;
    }
    
    //init sha3_224
    public byte init_224() {
        return init((short) 28);
    }
    
    //init sha3_256
    public byte init_256() {
        return init((short) 32);
    }
    
    //init sha3_384
    public byte init_384() {
        return init((short) 48);
    }
    
    //init sha3_512
    public byte init_512() {
        return init((short) 64);
    }
    
    //add more data into hash
    //input buffer, offset in buffer, byte length of message
    public void update(byte[] inBuff, short inOffset, short inLength) {
        short j = pt;
        short i;
        for (i = 0; i < inLength; i++) {
            //this is big endian
            st[j++] ^= inBuff[(byte) (inOffset + i)];
            if (j >= rsiz) {
                keccakf(st);
                j = 0;
            }
        }
        pt = j;
    }
    
    //generate hash of all data, reset engine
    //* TODO throws CryptoException.ILLEGAL_USE
    //* TODO nech sa sprava ako update plus posledne upravy a potom output (asi hotovo?)
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
        short i;
        
        update(inBuff, inOffset, inLength);
        
        st[pt] ^= 0x06;
        st[(short) (rsiz-1)] ^= 0x80;
        keccakf(st);
        for (i = 0; i < mdlen; i++) {
            outBuff[(short) (outOffset + i)] = st[i];
        }
        return mdlen;   
    }
    
}