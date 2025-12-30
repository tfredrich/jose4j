package org.jose4j.jwe;

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.JceProviderTestSupport;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT;

public class RsaKeyManagementMoreTest
{
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Test
    public void testSomeRoundTrips() throws Exception
    {
        RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);

        for (String alg : new String[] {KeyManagementAlgorithmIdentifiers.RSA1_5, KeyManagementAlgorithmIdentifiers.RSA_OAEP, KeyManagementAlgorithmIdentifiers.RSA_OAEP_256})
        {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
            jwe.setAlgorithmHeaderValue(alg);
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
            jwe.setPayload("stuff");
            jwe.setKey(rsaJsonWebKey.getPublicKey());
            String compactSerialization = jwe.getCompactSerialization();

            jwe = new JsonWebEncryption();
            jwe.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
            jwe.setCompactSerialization(compactSerialization);
            jwe.setKey(rsaJsonWebKey.getPrivateKey());
            Assert.assertEquals("stuff", jwe.getPlaintextString());
        }
    }

    @Test
    public void testSomeDecryptingWithTwoProviders() throws Exception
    {
        String jwkJson = "{\"kty\":\"RSA\"," +
               "\"n\":\"y_8p-sv8jFr5vFRvbVFOHBYQimII37mafhqZ7N__K-UbSTLysEa5gJeJb9SeAshsbzduWUnIks1v6zZ7PjyPKZcN9yi" +
                "3WRhK5TaTWZCmalqW3Pbz1POj0cEMJcxj6pYVxAGfOohNlPgfxyAQN3AnZG_dgu7F4LsRMnnlqkDHLqtRy3QijflAKP6gAHWIL" +
                "0xBGrMR0Rj_oLjKE-hk0QHgR0QNKXf4Nq8SgKazr9pzvm0dpb_shb5yEDp6agADleR6-KIcWd_bLWPsFzD1Ut9BgYkvRcKRICE" +
                "Or6uZwMtblW27TkLhcmc_7eFr0FH9g13KPD3GY_rYw92FFY1W1bVJlw\"," +
                "\"e\":\"AQAB\",\"d\":\"L2YI34ShGA2VZExsHYbcMstvqW-w5ybNfkp5BGBhflX7-oyTdiDgvj-3h9vroPLnuwmyop1xtKZ" +
                "2QD1G8oWIsB2weYKk41cxI8QEBbYF7MVCs3HP4uV_ZV_JDklI1_tqcEH-OM_t0tS6MX7CNddh18TkP6VyJc7hZoyLL_1gKnfqy" +
                "7nHMhr6UYUAucp2Db3tKqyj2SUB8h19QBlOUEc2yd0K1phWGGnGhME0uDRFJSiaaifsNxxbGbiFgp_d_nXvZzqjzWWjSBhkTRN" +
                "zL_JtQ9Y_nZJcuuhOAQL-WuC2yMrRPa0IHkwmvDtDxORhkx7V7gqx_1GXEaNGT94aPQT9rQ\",\"p\":\"3nCR0welBDxlOkAa" +
                "upt8IX49dkM_kzNZqxJXxbNwaJhh9EPN1sSU9cyvi3zxtVFgC9xLNaMDrSkUAu_vU14DuyyioaIXAP4pnbQTN6XqDL5kFzosi3" +
                "PaHsSCYHAcncY4TDnFqqjHnCSYKw_8nd819BezXq-NA1LQwLZjMi2YUAs\",\"q\":\"6sZCUKt9BUCtbtD8mfH-DfcyAehD1w" +
                "t-uJAGt3uNs1i1lb0JQ8mtH4KRpgK6HoGIK_30AZrKiPN_E8XLpi9BNWRRzkErs7cluNbebHXHqwcwos22An2zIVtAxVms-Tah" +
                "7XZHM5Z8fpExpjlZk7tzIHX7ltG_RX7_b64yo8SQKCU\",\"dp\":\"b8xuTn16H93nFtbfWEkLo53acFUuX-KgP84xVUlxxvB" +
                "H00g87aPSJpRg6p-6sGIc_vkSx_uNvnt19l_3jpQjFfFCMDDSlQopinzWZ9K5BvyuO8peVxy8VVh5GtVeXKIi65Th13uLD9yIq" +
                "qQXWJW2fV9oJL_hBPmbuDAzPSYTdq8\",\"dq\":\"e5ugxKpVa5OO_J5psH_Ze-7fVGO-fBVgRboG30nc5EVbbZgWrascTE_J" +
                "cXdUGMWoNUlC1Cl0Y0CYcoecXkXY9kx4SbjEUp2l7biraL1mP-TMNZtLLeqSiohqBL3fNWMPRGAWwtGDgHvfgR4GzKJPzhJwQQ" +
                "rzwppH0LwNi23tXEU\",\"qi\":\"wulvYLml_z8todGstRtwRDfI0vElBw2TR0x9V7XPmqZoVeKrySimVfccPGa6owfGC4wuu" +
                "_f-Dzdotk8BILHzKCyviLEIpN0d_OXEN14elAF8XjysL0bSg9tynxoYmdHs7GllDJHvy5HOcs_yuPmnkPvyP82kQy8xbr9nJuA" +
                "3L8Q\"}";

        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJson);

        final String jwe15 = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.K8XnfAap3iEz-PNojjoG6EEykHIqeBjNIL" +
                "5FV4bNTV8CiXG7VMVrL3XD7CnB-JRpeI0bgG46246AndJzg4HzINrY1TjlfdoPDCNsWbw2xyXVTLU7N1F8LjrtIpi8SwKm5DsEi" +
                "JBFbFpehE7fKi_op9eRkMrYO0TFGelWjMkSEo-yS2Tk46kfz-6EXdOdpo5bU6xGQ_dPA3Hl2c2g6cq8m7H3katE5LkQ2rpTcYDn" +
                "auwApb0CdZcWkOmC3xpGT89sGFMVOU5g1yRdGb40C_9-gdG9gFdoP4G5qW76he0KaSrdzXUGT_Z6EXGehj0B_bEes-L2sALROq_" +
                "0qKqiLkETRA.a74pDKBLkBr3ckxo2IW3fQ.hFlfVzjCNVCXiJ4J6sDHvA.giqvfcovD9D0f5A_faBVOQ";
        final String jweO = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.eJYoF3gHsJKqguSLhtFH8d9Ovsvk_Zbt" +
                "sM3h2naWLgMpQ1KivgQPncWicGjEqb7yl1xk7A5t2gC1g_DJkKsoAORLJG3d2JlC58c5VOjijAUQHqYou_ccmbIVRlj7q1x8P6u" +
                "Kgg5qrpZOstwlSzo8BFhLCVtyu8LXvy2agDRarp-qBytFbPSzKEkZCpRLlsimRxA329bVSwBqHzldTEy-iyeq8rilSqk4ZbRcRk" +
                "QOcf8hwPOOh0ypRJDX3f2TykNUHAcxrZREtDghMerJo4tgJyvPr2JKwK4O9BOfmya-LBxToa7sBy9R82DdqhSqGAWEItyiNKFhi" +
                "HooRMsIkgwNyw.XxVEmEuUzmGRc4mcC5siJQ.42xjNf15bd1FyB2-S79LLA.ln-qHy1AheX-sI0K_86Awg";
        final String jweO2 = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.xsj_3GCVi6qvrIZf0PmXYsOjBo" +
                "lsjpsaxxEMNovkLKJQa_6AMncztzLi3kctMicqV-38Ye-9pwGZYmxCkOGO0jSIKKAMowjD-HyqBgaR27bDl7R0CXV0pb_N2gjfb" +
                "IuxYOT77paLBxuu2tJYfkYi3HqC2rPF3Qm8hcgvrLYJAb_DanGonPcThrlYHoj9LuVeusxMvjj2DS-zZq35woSv3Hru4M4nPvT0" +
                "YB5RHUAasP26pdRod5I0ov9GDd7KPR170oOrjRsVu7gZiEZFJLUmNAP9tucF3y15dDxj-87h9k5-a9io7ftHUAHgdSvP53fA1ZR" +
                "qsPa5U-CsGGCxqytO4A.6gIDMTcnGfZabZKVM5tVGg.MHdKv34aT-JpWYIvVBjE_A.pRJ4H2M2tybSvnkI4pi2GA";

        for (String jweString : new String[] {jwe15, jweO, jweO2})
        {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
            jwe.setCompactSerialization(jweString);
            jwe.setKey(jwk.getPrivateKey());
            Assert.assertEquals("meh mode", jwe.getPlaintextString());

            ProviderContext pc = new ProviderContext();
            pc.getSuppliedKeyProviderContext().setKeyDecipherModeOverride(ProviderContext.KeyDecipherMode.DECRYPT);
            jwe = new JsonWebEncryption();
            jwe.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
            jwe.setProviderContext(pc);
            jwe.setCompactSerialization(jweString);
            jwe.setKey(jwk.getPrivateKey());
            Assert.assertEquals("meh mode", jwe.getPlaintextString());

            pc = new ProviderContext();
            pc.getSuppliedKeyProviderContext().setKeyDecipherModeOverride(ProviderContext.KeyDecipherMode.UNWRAP);
            jwe = new JsonWebEncryption();
            jwe.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
            jwe.setProviderContext(pc);
            jwe.setCompactSerialization(jweString);
            jwe.setKey(jwk.getPrivateKey());
            Assert.assertEquals("meh mode", jwe.getPlaintextString());
        }

        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setUseBouncyCastleRegardlessOfAlgs(true);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                for (String jweString : new String[] {jwe15, jweO, jweO2})
                {
                    JsonWebEncryption jwe = new JsonWebEncryption();
                    jwe.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
                    jwe.setCompactSerialization(jweString);
                    jwe.setKey(jwk.getPrivateKey());
                    Assert.assertEquals("meh mode", jwe.getPlaintextString());
                }
            }
        });
    }

    @Test
    public void someNegativeInputs() throws Exception
    {
        String jwkJson = "{\n" +
            "        \"kty\": \"RSA\",\n" +
            "        \"alg\": \"RSA1_5\",\n" +
            "        \"use\": \"enc\",\n" +
            "        \"n\": \"w2A4cbwOAK4ATnwXkGWereqv9dkEcgAGHc9g-cjo1HFeilYirvfD2Un2vQxW_6g2OKRPmmo46vMZFMYv_V57174j411y-NQlZGb7iFqMQADzo60VZ7vpvAX_NuxNGxYR-N2cBgvgqDiGAoO9ouNdhuHhxipTjGVfrPUpxmJtNPZpxsgxQWSpYCYMl304DD_5wWrnumNNIKOaVsAYmjFPV_wqxFCHbitPd1BG9SwXPk7wAHtXT6rYaUImS_OKaHkTO1OO0PNhd3-wJRNMCh_EGUwAghfWgFyAd20pQLZamamxgHvfL4-0hwuzndhHt0ye-gRVTtXDFEwABB--zwvlCw\",\n" +
            "        \"e\": \"AQAB\",\n" +
            "        \"kid\": \"rsa1_5\",\n" +
            "        \"d\": \"EjMvbuDeyQ9sdeM3arscqgTXuWYq9Netui8sUHh3v_qDnQ1jE7t-4gny0y-IFy67RlGAHNlSTgixSG8h309i5_kNbMuyvx08EntJaS1OLVQpXhDskoo9vscsPBiNIj3PFMjIFQQcPG9vhGJzUu4tMzhtiME-oTB8VidMae-XTryPvozTu4rgfb4U7uauvLqESLz3A5xtzPnwNwqXAIlrdxU-MT_iln08on_QIF8afWUqCbsWWjEck_QDKLVpzh8VV9kkEVWwYfCFhHBwS-fgGJJTE3gK4HwOokydMtH95Dzj47MA2pLe600l7ioyGSPltcv967NtOpxMPM5ro751KQ\",\n" +
            "        \"p\": \"-F1u3NAMWPu1TIuvIywIjh5fuiA3AVKLgS6Fw_hAi3M9c3T7E1zNJZuHgQExJEu06ZPfzye9m7taDzh-Vw4VGDED_MZedsE2jEsWa9EKeq3bZVf5j81FLCHH8BicFqrPjvoVUC35wrl9SGJzaOa7KXxD2jW22umYjJS_kcopvf0\",\n" +
            "        \"q\": \"yWHG7jHqvfqT8gfhIlxpMbeJ02FrWIkgJC-zOJ26wXC6oxPeqhqEO7ulGqZPngNDdSGgWcQ7noGEU8O4MA9V3yhl91TFZy8unox0sGe0jDMwtxm3saXtTsjTE7FBxzcR0PubfyGiS0fJqQcj8oJSWzZPkUshzZ8rF3jTLc8UWac\",\n" +
            "        \"dp\": \"Va9WWhPkzqY4TCo8x_OfF_jeqcYHdAtYWb8FIzD4g6PEZZrMLEft9rWLsDQLEiyUQ6lio4NgZOPkFDA3Vi1jla8DYyfE20-ZVBlrqNK7vMtST8pkLPpyjOEyq2CyKRfQ99DLnZfe_RElad2dV2mS1KMsfZHeffPtT0LaPJ_0erk\",\n" +
            "        \"dq\": \"M8rA1cviun9yg0HBhgvMRiwU91dLu1Zw_L2D02DFgjCS35QhpQ_yyEYHPWZefZ4LQFmoms2cI7TdqolgmoOnKyCBsO2NY29AByjKbgAN8CzOL5kepEKvWJ7PonXpG-ou29eJ81VcHw5Ub_NVLG6V7b13E0AGbpKsC3pYnaRvcGs\",\n" +
            "        \"qi\": \"8zIqISvddJYC93hP0sKkdHuVd-Mes_gsbi8xqSFYGqc-wSU12KjzHnZmBuJl_VTGy9CO9W4K2gejr588a3Ozf9U5hx9qCVkV0_ttxHcTRem5sFPe9z-HkQE5IMW3SdmL1sEcvkzD7z8QhcHRpp5aMptfuwnxBPY8U449_iNgXd4\"\n" +
            "      }";

        PublicJsonWebKey publicJwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJson);
        RsaJsonWebKey rsaJwk = (RsaJsonWebKey) publicJwk;

         // should not have distinguishable behavior for the two test cases below:

        // The first ciphertext below contains an invalid PKCS #1 padding.
        String first = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0" +
                ".ksmeZ6dBbP0UfDEaLXlqPl2XDaAA29kGlKtDb89x-4xN5-A6bx2umI_ToHK2GadzxUOgKROCACYb6rmKsqsQCOZaBsnq_4mDII1W0pja7Lz4zTnr7R3O4kALg4zXqG-gSlcDA7k1NgkpMDS15PjMmADqyqxbxQsXdfjstN324iqdvYGh6NsckkfTSWxDVAqiSR9fW8PsIbo3uSMokNaC-f64CDWIB9AsCxhF-3mnFbxXNxw7JE0upOgG4enQ8kZkwi_v54HBqAau1YNW7gPhFV8ElTQ71J6aHB3dja23lbWdaJmrK6PJE7gEeZmUbFkSYmuyzRUS-NGfXA23fYv5JQ" +
                ".46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEEHiaqhiQ";

        // The second ciphertext below contains valid PKCS #1 padding, but the size of the encoded key is incorrect.
        String second = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0" +
                ".oyVTmkyoChxFtyCtiKhv8OpBJcV6C6s_gMFSSRJBNStpdHPzq2YmroTfXGj1J1plFG4BBQwIZtdt6rIS6YkCvTLGqP1hds9CAO1a_bgRyoAVuOVvH2vmz5U2r74_SRbAzD35M7yZ_tSnnEdMFlHMFbf5uNwmgArrtPgh0V5OLn5i4XIc154FLTiQlvAEhUxiPuYBkm_1GBiYEH4JjP2RKXAUx_TxAVwPsOfIPAVrO0Ev_nvdtVLCE-uOn8WQbxh4wwOztaXOV1HIaPrl7HN-YtDOA840QUHm97ZZLAPRgLzGlkMI0ZS8QkYdb9_FT3KMbNu60nBKEniv2uhBdIhM9g" +
                ".46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEEHiaqhiQ";


        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.RSA1_5));
        jwe.setKey(rsaJwk.getPrivateKey());
        jwe.setCompactSerialization(first);

        try
        {
            jwe.getPlaintextString();
        }
        catch (JoseException e)
        {
            log.debug(ExceptionHelp.toStringWithCauses(e));
            Assert.assertTrue(e.getMessage().contains("Tag mismatch"));
        }

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.RSA1_5));
        jwe.setKey(rsaJwk.getPrivateKey());
        jwe.setCompactSerialization(second);

        try
        {
            jwe.getPlaintextString();
        }
        catch (JoseException e)
        {
            log.debug(ExceptionHelp.toStringWithCauses(e));
            Assert.assertTrue(e.getMessage().contains("Tag mismatch"));
        }

        jwkJson =  "{\n" +
                "        \"alg\": \"RSA-OAEP\",\n" +
                "        \"use\": \"enc\",\n" +
                "        \"n\": \"kqGboBfAWttWPCA-0cGRgsY6SaYoIARt0B_PkaEcIq9HPYNdu9n6UuWHuuTHrjF_ZoQW97r5HaAorNvrMEGTGdxCHZdEtkHvNVVmrtxTBLiQCbCozXhFoIrVcr3qUBrdGnNn_M3jJi7Wg7p_-x62nS5gNG875oyheRkutHsQXikFZwsN3q_TsPNOVlCiHy8mxzaFTUQGm-X8UYexFyAivlDSjgDJLAZSWfxd7k9Gxuwa3AUfQqQcVcegmgKGCaErQ3qQbh1x7WB6iopE3_-GZ8HMAVtR9AmrVscqYsnjhaCehfAI0iKKs8zXr8tISc0ORbaalrkk03H1ZrsEnDKEWQ\",\n" +
                "        \"e\": \"AQAB\",\n" +
                "        \"d\": \"YsfIRYN6rDqSz5KRf1E9q7HK1o6-_UK-j7S-asb0Y1FdVs1GuiRQhMPoOjmhY3Io93EI3_7vj8uzWzAUMsAaTxOY3sJnIbktYuqTcD0xGD8VmdGPBkx963db8B6M2UYfqZARf7dbzP9EuB1N1miMcTsqyGgfHGOk7CXQ1vkIv8Uww38KMtEdJ3iB8r-f3qcu-UJjE7Egw9CxKOMjArOXxZEr4VnoIXrImrcTxBfjdY8GbzXGATiPQLur5GT99ZDW78falsir-b5Ean6HNyOeuaJuceT-yjgCXn57Rd3oIHD94CrjNtjBusoLdjbr489L8K9ksCh1gynzLGkeeWgVGQ\",\n" +
                "        \"p\": \"0xalbl1PJbSBGD4XOjIYJLwMYyHMiM06SBauMGzBfCask5DN5jH68Kw1yPS4wkLpx4ltGLuy0X5mMaZzrSOkBGb27-NizBgB2-L279XotznWeh2jbF05Kqzkoz3VaX_7dRhCHEhOopMQh619hA1bwaJyW1k8aNlLPTl3BotkP4M\",\n" +
                "        \"q\": \"sdQsQVz3tI7hmisAgiIjppOssEnZaZO0ONeRRDxBHGLe3BCo1FJoMMQryOAlglayjQnnWjQ-BpwUpa0r9YQhVLweoNEIig6Beph7iYRZgOHEiiTTgUIGgXAL6xhsby1PueUfT0xsN1Y7qt5f5EwOfu7tnFqNyJXIp9W1NQgU6fM\",\n" +
                "        \"dp\": \"kEpEnuJNfdqa-_VFb1RayJF6bjDmXQTcN_a47wUIZVMSWHR9KkMz41v0D_-oY7HVl73Kw0NagnVCaeH75HgeX5v6ZBQsrpIigynr3hl8T_LLNwIXebVnpFI2n5de0BTZ0DraxfZvOhYJEJV43NE8zWm7fdHLx2fxVFJ5mBGkXv0\",\n" +
                "        \"dq\": \"U_xJCnXF51iz5AP7MXq-K6YDIR8_t0UzEMV-riNm_OkVKAoWMnDZFG8R3sU98djQaxwKT-fsg2KjvbuTz1igBUzzijAvQESpkiUB82i2fNAj6rqJybpNKESq3FWkoL1dsgYsS19knJ31gDWWRFRHZFujjPyXiexz4BBmjK1Mc1E\",\n" +
                "        \"qi\": \"Uvb84tWiJF3fB-U9wZSPi7juGgrzeXS_LYtf5fcdV0fZg_h_5nSVpXyYyQ-PK218qEC5MlDkaHKRD9wBOe_eU_zJTNoXzB2oAcgl2MapBWUMytbiF84ghP_2K9UD63ZVsyrorSZhmsJIBBuqQjrmk0tIdpMdlMxLYhrbYwFxUqc\",\n" +
                "        \"kid\": \"kid-rsa-enc-oaep\",\n" +
                "        \"kty\": \"RSA\"\n" +
                "      }";

        publicJwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJson);
        rsaJwk = (RsaJsonWebKey) publicJwk;

        // RSA-OAEP w/ the alg header changed RSA1_5

        String third = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0." +
                "CuUuY9PH2wWjuLXd5O9LLFanwyt5-y-NzEpy9rC3A63tFsvdp8GWP1kRt1d3zd0bGqakwls623VQxzxqQ25j5gdHh8dKMl67xTLHt1Qlg36nI9Ukn7syq25VrzfrRRwy0k7isqMncHpzuBQlmfzPrszW7d13z7_ex0Uha869RaP-W2NNBfHYw26xIXcCSVIPg8jTLA7h6QmOetEej-NXXcWrRKQgBRapYy4iWrij9Vr3JzAGSHVtIID74tFOm01FdJj4s1M4IXegDbvAdQb6Vao1Ln5GolnTki4IGvH5FDssDHz6MS2JG5QBcITzfuXU81vDC00xzNEuMat0AngmOw" +
                ".UjPQbnakkZYUdoDa.vcbS.WQ_bOPiGKjPSq-qyGOIfjA";

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
        jwe.setKey(rsaJwk.getPrivateKey());
        jwe.setCompactSerialization(third);

        try
        {
            jwe.getPlaintextString();
        }
        catch (JoseException e)
        {
            log.debug(ExceptionHelp.toStringWithCauses(e));
            Assert.assertTrue(e.getMessage().contains("Tag mismatch"));
        }
    }
}
