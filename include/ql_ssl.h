/*****************************************************************************
*  Copyright Statement:
*  --------------------
*  This software is protected by Copyright and the information contained
*  herein is confidential. The software may not be copied and the information
*  contained herein may not be used or disclosed except with the written
*  permission of Quectel Co., Ltd. 2020
*
*****************************************************************************/
/*****************************************************************************
 *
 * Filename:
 * ---------
 *   ql_ssl.h 
 *
 * Project:
 * --------
 *   QuecOpen
 *
 * Description:
 * ------------
 *   socket APIs defines.
 *
 * Author:
 * -------
 * -------
 *
 *============================================================================
 *             HISTORY
 *----------------------------------------------------------------------------
 * 
 ****************************************************************************/

 
#ifndef __QL_SSL_H__
#define __QL_SSL_H__

#define SHA_SIZE  20
#define ASN_NAME_MAX 256
#define EXTERNAL_SERIAL_SIZE 32
#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE 8
#define DES_KS_SIZE    32

#define MD5_DIGEST_SIZE 16
#define SHA_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32

/* the infamous mp_int structure */
typedef struct  {
    int used, alloc, sign;
    mp_digit *dp;
} mp_int;

/* RSA */
typedef struct RsaKey {
    mp_int n, e, d, p, q, dP, dQ, u;
    int   type;                               /* public or private */
    void* heap;                               /* for user memory overrides */
#ifdef HAVE_CAVIUM
    int    devId;           /* nitrox device id */
    word32 magic;           /* using cavium magic */
    word64 contextHandle;   /* nitrox context memory handle */
    byte*  c_n;             /* cavium byte buffers for key parts */
    byte*  c_e;
    byte*  c_d;
    byte*  c_p;
    byte*  c_q;
    byte*  c_dP;
    byte*  c_dQ;
    byte*  c_u;             /* sizes in bytes */
    word16 c_nSz, c_eSz, c_dSz, c_pSz, c_qSz, c_dP_Sz, c_dQ_Sz, c_uSz;
#endif
} RsaKey;

/* DES3 encryption and decryption */
typedef struct Des3 {
    word32 key[3][DES_KS_SIZE];
    word32 reg[DES_BLOCK_SIZE / sizeof(word32)];      /* for CBC mode */
    word32 tmp[DES_BLOCK_SIZE / sizeof(word32)];      /* same         */
#ifdef HAVE_CAVIUM
    int     devId;           /* nitrox device id */
    word32  magic;           /* using cavium magic */
    word64  contextHandle;   /* nitrox context memory handle */
#endif
} Des3;

/* OS specific seeder */
typedef struct OS_Seed {
    #if defined(USE_WINDOWS_API)
        ProviderHandle handle;
    #else
        int fd;
    #endif
} OS_Seed;

enum {
	ARC4_ENC_TYPE   = 4,    /* cipher unique type */
    ARC4_STATE_SIZE = 256
};

/* ARC4 encryption and decryption */
typedef struct Arc4 {
    byte x;
    byte y;
    byte state[ARC4_STATE_SIZE];
#ifdef HAVE_CAVIUM
    int    devId;           /* nitrox device id */
    word32 magic;           /* using cavium magic */
    word64 contextHandle;   /* nitrox context memory handle */
#endif
} Arc4;

typedef struct RNG {
    OS_Seed seed;
    Arc4    cipher;
#ifdef HAVE_CAVIUM
    int    devId;           /* nitrox device id */
    word32 magic;           /* using cavium magic */
#endif
} RNG;



/* error codes */
enum {
		RSA_BUFFER_E       = -131,  /* RSA buffer error, output too small or input too large */
		ASN_PARSE_E        = -140,  /* ASN parsing error, invalid input */
		ASN_TAG_NULL_E     = -145,  /* ASN tag error, not null */
		ASN_EXPECT_0_E     = -146,  /* ASN expect error, not zero */
		ASN_BITSTR_E       = -147,  /* ASN bit string error, wrong id */
		ASN_INPUT_E        = -154,  /* ASN input error, not enough data */
		BAD_FUNC_ARG       = -173,  /* Bad function argument provided */
}Enum_SSL_ErrCode;


/*****************************************************************
* Function: 	Ql_SSL_Base64_Encode 
* 
* Description:
*				
*				Convert data to Base64 encoding format
*
* Parameters:
*				in:
*					[In] Data to be encoded
*				inLen:	 
*					[In] Data length.
*				out:
*					[out]  Encoded data.
*				outLen:
*					[In&out]  The size of "out" buf needs to be passed in first, and then the length of the encoded data is given.
*
*
* Return:		 
*				QL_RET_OK, this function succeeds.
*				Other error codes, please see "Enum_SSL_ErrCode"
*****************************************************************/
s32 Ql_SSL_Base64_Encode(const byte* in, word32 inLen, byte* out, word32* outLen);


/*****************************************************************
* Function: 	Ql_SSL_Base64_Decode 
* 
* Description:
*				
*				Decode Base64 data.
*
* Parameters:
*				in:
*					[In] Data to be decoded
*				inLen:	
*					[In]  Data length.
*				out:
*					[out]  Decoded data.
*				outLen:
*					[In&out]  The size of "out" buf needs to be passed in first, and then the length of the decoded data is given.
*
*
* Return:		 
*				QL_RET_OK, this function succeeds.
*				Other error codes, please see "Enum_SSL_ErrCode"
****************************************************************/
s32 Ql_SSL_Base64_Decode(const byte* in, word32 inLen, byte* out, word32* outLen);


/*****************************************************************
* Function: 	Ql_SSL_Rng 
* 
* Description:
*				
*				Generate random numbers.
*
* Parameters:
*				
*				rng:  
*					[out]   Random generated.
*				
* Return:		 
*				QL_RET_OK or  QL_RET_ERR_PARAM. 
*				
****************************************************************/
s32 Ql_SSL_Rng(RNG* rng); 

/*****************************************************************
* Function: 	Ql_SSL_RsaPublicKeyDecode 
* 
* Description:
*				
*				Generate RSA  public key.
*
* Parameters:
*				input:
*					[In] Enter certificate.
*				inOutIdx:	
*					[In]  Output Data.
*				key:  
*					[out]  RSA  public key.
*				inSz:   
*					[In]  "input" length.
*				
* Return:		 
*				QL_RET_OK.
*				Other error codes, please see "Enum_SSL_ErrCode"
****************************************************************/
s32 Ql_SSL_RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key, word32 inSz);


/*****************************************************************
* Function: 	Ql_SSL_RsaPrivateKeyDecode 
* 
* Description:
*				
*				Generate RSA  private key.
*
* Parameters:
*				input:
*					[In] Enter certificate.
*				inOutIdx:	
*					[In]  Output Data.
*				key:  
*					[out]  RSA  private key.
*				inSz:   
*					[In]  "input" length.
*				
* Return:		 
*				QL_RET_OK.
*				Other error codes, please see "Enum_SSL_ErrCode"
****************************************************************/
s32 Ql_SSL_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key, word32 inSz);


/*****************************************************************
* Function: 	Ql_SSL_RsaPublicEncrypt 
* 
* Description:
*				
*				RSA public key encryption.
*
* Parameters:
*				in:
*					[In] Data to be Encrypt
*				inLen:	
*					[In]  Data length.
*				out:  
*					[out]  Encrypt data.
*				outLen:
*					[In&out]  The size of "out" buf needs to be passed in first, and then the length of the "out" data is given.
*				key:   
*					[In]  Encryption key.
*				rng:   
*					[In]  Random number.
*
*				
* Return:		 
*				
*				Other error codes, please see "Enum_SSL_ErrCode"
****************************************************************/
s32 Ql_SSL_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key,RNG* rng);


/*****************************************************************
* Function: 	Ql_SSL_RsaPrivateDecrypt 
* 
* Description:
*				
*				RSA private key decryption.
*
* Parameters:
*				in:
*					[In] Data to be Decrypt 
*				inLen:	
*					[In]  Data length.
*				out:  
*					[out]  Decrypt data.
*				outLen:
*					[In&out]  The size of "out" buf needs to be passed in first, and then the length of the "out" data is given.
*				key:   
*					[In]  Decryption key.
*				
* Return:		 
*				
*				Other error codes, please see "Enum_SSL_ErrCode"
****************************************************************/
s32 Ql_SSL_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key);


#endif

