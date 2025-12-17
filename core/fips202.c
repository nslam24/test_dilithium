/*
 * fips202.c - FIPS 202 (SHA-3) implementation
 * 
 * Based on the official CRYSTALS-Dilithium reference implementation
 * Implements SHAKE-128 and SHAKE-256 for matrix generation
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "fips202.h"

#define NROUNDS 24

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/*************************************************
* Name:        ROL64
*
* Description: Rotate left by n bits
**************************************************/
#define ROL64(a, offset) ((a << offset) ^ (a >> (64-offset)))

/*************************************************
* Name:        KeccakF1600_StatePermute
*
* Description: The Keccak F1600 Permutation
*
* Arguments:   - uint64_t *state: pointer to input/output Keccak state
**************************************************/
static void KeccakF1600_StatePermute(uint64_t state[25])
{
    int round;

    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    //copyFromState(A, state)
    Aba = state[ 0];
    Abe = state[ 1];
    Abi = state[ 2];
    Abo = state[ 3];
    Abu = state[ 4];
    Aga = state[ 5];
    Age = state[ 6];
    Agi = state[ 7];
    Ago = state[ 8];
    Agu = state[ 9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for(round = 0; round < NROUNDS; round += 2) {
        //    prepareTheta
        BCa = Aba^Aga^Aka^Ama^Asa;
        BCe = Abe^Age^Ake^Ame^Ase;
        BCi = Abi^Agi^Aki^Ami^Asi;
        BCo = Abo^Ago^Ako^Amo^Aso;
        BCu = Abu^Agu^Aku^Amu^Asu;

        //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        Da = BCu^ROL64(BCe, 1);
        De = BCa^ROL64(BCi, 1);
        Di = BCe^ROL64(BCo, 1);
        Do = BCi^ROL64(BCu, 1);
        Du = BCo^ROL64(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL64(Age, 44);
        Aki ^= Di;
        BCi = ROL64(Aki, 43);
        Amo ^= Do;
        BCo = ROL64(Amo, 21);
        Asu ^= Du;
        BCu = ROL64(Asu, 14);
        Eba =   BCa ^((~BCe)&  BCi );
        Eba ^= (uint64_t)KeccakF_RoundConstants[round];
        Ebe =   BCe ^((~BCi)&  BCo );
        Ebi =   BCi ^((~BCo)&  BCu );
        Ebo =   BCo ^((~BCu)&  BCa );
        Ebu =   BCu ^((~BCa)&  BCe );

        Abo ^= Do;
        BCa = ROL64(Abo, 28);
        Agu ^= Du;
        BCe = ROL64(Agu, 20);
        Aka ^= Da;
        BCi = ROL64(Aka,  3);
        Ame ^= De;
        BCo = ROL64(Ame, 45);
        Asi ^= Di;
        BCu = ROL64(Asi, 61);
        Ega =   BCa ^((~BCe)&  BCi );
        Ege =   BCe ^((~BCi)&  BCo );
        Egi =   BCi ^((~BCo)&  BCu );
        Ego =   BCo ^((~BCu)&  BCa );
        Egu =   BCu ^((~BCa)&  BCe );

        Abe ^= De;
        BCa = ROL64(Abe,  1);
        Agi ^= Di;
        BCe = ROL64(Agi,  6);
        Ako ^= Do;
        BCi = ROL64(Ako, 25);
        Amu ^= Du;
        BCo = ROL64(Amu,  8);
        Asa ^= Da;
        BCu = ROL64(Asa, 18);
        Eka =   BCa ^((~BCe)&  BCi );
        Eke =   BCe ^((~BCi)&  BCo );
        Eki =   BCi ^((~BCo)&  BCu );
        Eko =   BCo ^((~BCu)&  BCa );
        Eku =   BCu ^((~BCa)&  BCe );

        Abu ^= Du;
        BCa = ROL64(Abu, 27);
        Aga ^= Da;
        BCe = ROL64(Aga, 36);
        Ake ^= De;
        BCi = ROL64(Ake, 10);
        Ami ^= Di;
        BCo = ROL64(Ami, 15);
        Aso ^= Do;
        BCu = ROL64(Aso, 56);
        Ema =   BCa ^((~BCe)&  BCi );
        Eme =   BCe ^((~BCi)&  BCo );
        Emi =   BCi ^((~BCo)&  BCu );
        Emo =   BCo ^((~BCu)&  BCa );
        Emu =   BCu ^((~BCa)&  BCe );

        Abi ^= Di;
        BCa = ROL64(Abi, 62);
        Ago ^= Do;
        BCe = ROL64(Ago, 55);
        Aku ^= Du;
        BCi = ROL64(Aku, 39);
        Ama ^= Da;
        BCo = ROL64(Ama, 41);
        Ase ^= De;
        BCu = ROL64(Ase,  2);
        Esa =   BCa ^((~BCe)&  BCi );
        Ese =   BCe ^((~BCi)&  BCo );
        Esi =   BCi ^((~BCo)&  BCu );
        Eso =   BCo ^((~BCu)&  BCa );
        Esu =   BCu ^((~BCa)&  BCe );

        //    prepareTheta
        BCa = Eba^Ega^Eka^Ema^Esa;
        BCe = Ebe^Ege^Eke^Eme^Ese;
        BCi = Ebi^Egi^Eki^Emi^Esi;
        BCo = Ebo^Ego^Eko^Emo^Eso;
        BCu = Ebu^Egu^Eku^Emu^Esu;

        //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu^ROL64(BCe, 1);
        De = BCa^ROL64(BCi, 1);
        Di = BCe^ROL64(BCo, 1);
        Do = BCi^ROL64(BCu, 1);
        Du = BCo^ROL64(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL64(Ege, 44);
        Eki ^= Di;
        BCi = ROL64(Eki, 43);
        Emo ^= Do;
        BCo = ROL64(Emo, 21);
        Esu ^= Du;
        BCu = ROL64(Esu, 14);
        Aba =   BCa ^((~BCe)&  BCi );
        Aba ^= (uint64_t)KeccakF_RoundConstants[round+1];
        Abe =   BCe ^((~BCi)&  BCo );
        Abi =   BCi ^((~BCo)&  BCu );
        Abo =   BCo ^((~BCu)&  BCa );
        Abu =   BCu ^((~BCa)&  BCe );

        Ebo ^= Do;
        BCa = ROL64(Ebo, 28);
        Egu ^= Du;
        BCe = ROL64(Egu, 20);
        Eka ^= Da;
        BCi = ROL64(Eka, 3);
        Eme ^= De;
        BCo = ROL64(Eme, 45);
        Esi ^= Di;
        BCu = ROL64(Esi, 61);
        Aga =   BCa ^((~BCe)&  BCi );
        Age =   BCe ^((~BCi)&  BCo );
        Agi =   BCi ^((~BCo)&  BCu );
        Ago =   BCo ^((~BCu)&  BCa );
        Agu =   BCu ^((~BCa)&  BCe );

        Ebe ^= De;
        BCa = ROL64(Ebe, 1);
        Egi ^= Di;
        BCe = ROL64(Egi, 6);
        Eko ^= Do;
        BCi = ROL64(Eko, 25);
        Emu ^= Du;
        BCo = ROL64(Emu, 8);
        Esa ^= Da;
        BCu = ROL64(Esa, 18);
        Aka =   BCa ^((~BCe)&  BCi );
        Ake =   BCe ^((~BCi)&  BCo );
        Aki =   BCi ^((~BCo)&  BCu );
        Ako =   BCo ^((~BCu)&  BCa );
        Aku =   BCu ^((~BCa)&  BCe );

        Ebu ^= Du;
        BCa = ROL64(Ebu, 27);
        Ega ^= Da;
        BCe = ROL64(Ega, 36);
        Eke ^= De;
        BCi = ROL64(Eke, 10);
        Emi ^= Di;
        BCo = ROL64(Emi, 15);
        Eso ^= Do;
        BCu = ROL64(Eso, 56);
        Ama =   BCa ^((~BCe)&  BCi );
        Ame =   BCe ^((~BCi)&  BCo );
        Ami =   BCi ^((~BCo)&  BCu );
        Amo =   BCo ^((~BCu)&  BCa );
        Amu =   BCu ^((~BCa)&  BCe );

        Ebi ^= Di;
        BCa = ROL64(Ebi, 62);
        Ego ^= Do;
        BCe = ROL64(Ego, 55);
        Eku ^= Du;
        BCi = ROL64(Eku, 39);
        Ema ^= Da;
        BCo = ROL64(Ema, 41);
        Ese ^= De;
        BCu = ROL64(Ese, 2);
        Asa =   BCa ^((~BCe)&  BCi );
        Ase =   BCe ^((~BCi)&  BCo );
        Asi =   BCi ^((~BCo)&  BCu );
        Aso =   BCo ^((~BCu)&  BCa );
        Asu =   BCu ^((~BCa)&  BCe );
    }

    //copyToState(state, A)
    state[ 0] = Aba;
    state[ 1] = Abe;
    state[ 2] = Abi;
    state[ 3] = Abo;
    state[ 4] = Abu;
    state[ 5] = Aga;
    state[ 6] = Age;
    state[ 7] = Agi;
    state[ 8] = Ago;
    state[ 9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

/*************************************************
* Name:        keccak_absorb
*
* Description: Absorb step of Keccak; incremental.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
*              - size_t r: rate in bytes (e.g., 168 for SHAKE128)
*              - uint8_t p: domain-separation byte for different Keccak-derived functions
**************************************************/
static void keccak_absorb(keccak_state *state,
                          const uint8_t *in,
                          size_t inlen,
                          size_t r,
                          uint8_t p)
{
    size_t i;

    for(i = 0; i < 25; ++i)
        state->s[i] = 0;
    state->pos = 0;

    while(inlen >= r) {
        for(i = 0; i < r / 8; ++i)
            state->s[i] ^= ((uint64_t*)in)[i];
        in += r;
        inlen -= r;
        KeccakF1600_StatePermute(state->s);
    }

    for(i = 0; i < inlen; ++i)
        ((uint8_t*)state->s)[i] ^= in[i];

    ((uint8_t*)state->s)[inlen] ^= p;
    ((uint8_t*)state->s)[r - 1] ^= 128;
    state->pos = inlen;
}

/*************************************************
* Name:        keccak_squeezeblocks
*
* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to out)
*              - keccak_state *s: pointer to input/output Keccak state
*              - size_t r: rate in bytes (e.g., 168 for SHAKE128)
**************************************************/
static void keccak_squeezeblocks(uint8_t *out,
                                 size_t nblocks,
                                 keccak_state *state,
                                 size_t r)
{
    size_t i;

    while(nblocks > 0) {
        KeccakF1600_StatePermute(state->s);
        for(i = 0; i < r / 8; ++i)
            ((uint64_t*)out)[i] = state->s[i];
        out += r;
        --nblocks;
    }
}

/*************************************************
* Name:        shake128_init
*
* Description: Initialize Keccak state for SHAKE-128
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
**************************************************/
void shake128_init(keccak_state *state)
{
    unsigned int i;
    for(i = 0; i < 25; ++i)
        state->s[i] = 0;
    state->pos = 0;
}

/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of SHAKE-128 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
    size_t i;

    while(inlen > 0) {
        size_t absorb = (inlen < SHAKE128_RATE - state->pos) ? inlen : (SHAKE128_RATE - state->pos);
        
        for(i = 0; i < absorb; ++i)
            ((uint8_t*)state->s)[state->pos + i] ^= in[i];
        
        in += absorb;
        inlen -= absorb;
        state->pos += absorb;
        
        if(state->pos == SHAKE128_RATE) {
            KeccakF1600_StatePermute(state->s);
            state->pos = 0;
        }
    }
}

/*************************************************
* Name:        shake128_finalize
*
* Description: Finalize absorb step.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
void shake128_finalize(keccak_state *state)
{
    ((uint8_t*)state->s)[state->pos] ^= 0x1F;
    ((uint8_t*)state->s)[SHAKE128_RATE - 1] ^= 128;
    state->pos = SHAKE128_RATE;
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE-128 XOF. Squeezes full blocks of
*              SHAKE128_RATE bytes each. Can be called multiple times
*              to keep squeezing. Modifies the state.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to out)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
    keccak_squeezeblocks(out, nblocks, state, SHAKE128_RATE);
}

/*************************************************
* Name:        shake256_init
*
* Description: Initialize Keccak state for SHAKE-256
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
**************************************************/
void shake256_init(keccak_state *state)
{
    unsigned int i;
    for(i = 0; i < 25; ++i)
        state->s[i] = 0;
    state->pos = 0;
}

/*************************************************
* Name:        shake256_absorb
*
* Description: Absorb step of SHAKE-256 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
    size_t i;

    while(inlen > 0) {
        size_t absorb = (inlen < SHAKE256_RATE - state->pos) ? inlen : (SHAKE256_RATE - state->pos);
        
        for(i = 0; i < absorb; ++i)
            ((uint8_t*)state->s)[state->pos + i] ^= in[i];
        
        in += absorb;
        inlen -= absorb;
        state->pos += absorb;
        
        if(state->pos == SHAKE256_RATE) {
            KeccakF1600_StatePermute(state->s);
            state->pos = 0;
        }
    }
}

/*************************************************
* Name:        shake256_finalize
*
* Description: Finalize absorb step.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
void shake256_finalize(keccak_state *state)
{
    ((uint8_t*)state->s)[state->pos] ^= 0x1F;
    ((uint8_t*)state->s)[SHAKE256_RATE - 1] ^= 128;
    state->pos = SHAKE256_RATE;
}

/*************************************************
* Name:        shake256_squeezeblocks
*
* Description: Squeeze step of SHAKE-256 XOF. Squeezes full blocks of
*              SHAKE256_RATE bytes each. Can be called multiple times
*              to keep squeezing. Modifies the state.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to out)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
    keccak_squeezeblocks(out, nblocks, state, SHAKE256_RATE);
}
