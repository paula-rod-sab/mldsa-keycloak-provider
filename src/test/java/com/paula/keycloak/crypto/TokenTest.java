package com.paula.keycloak.crypto;

import java.io.IOException;

import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.ObjectMapper;

public class TokenTest {
    
    public static void main(String[] args) throws JWSInputException, IOException {

        String tokenString = "eyJhbGciOiJNTC1EU0EtNDQiLCJ0eXAiIDogIkpXVCIsImtpZCIgOiAibWwtZHNhLWtleSJ9.eyJleHAiOjE3NTQzODQxNzMsImlhdCI6MTc1NDM4Mzg3MywianRpIjoib25ydHJvOmI3YzA1MzkwLTVlNGQtNGVlYS05MjZmLWJhYmQ0NjY0OTMzMSIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9yZWFsbXMvZGVtby1yZWFsbSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI1N2I4ZmRjMy1hNGMwLTQ4NWUtYThhNi00YWY4NTFiMjk0NGIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJtbC1kc2EtdGVzdC1jbGllbnQiLCJzaWQiOiI5NjI2YWUxMi04ZDQ4LTRhNWYtOWVjZi1kNzRhZjBkNTdmYmMiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJkZWZhdWx0LXJvbGVzLWRlbW8tcmVhbG0iLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQYXVsYSBSb2Ryw61ndWV6IiwicHJlZmVycmVkX3VzZXJuYW1lIjoicGF1bGEiLCJnaXZlbl9uYW1lIjoiUGF1bGEiLCJmYW1pbHlfbmFtZSI6IlJvZHLDrWd1ZXoiLCJlbWFpbCI6InBhdWxhcm9kcmlndWV6c2FiaWRvQGhvdG1haWwuY29tIn0.PrieIzLqIYApZgh-d70pKUfVD3TUqgs6tO7QAxoX0oMqfgPXyW6d8sHjYjUToOVx8XsHjpCaJG0l0hAj49E84dm2Kc7rXkYqz11yU-i_4qhfRnuoINC4o85xWJeHFq9w6V1LSOYxSA7RGPSJgyByDatcTTwZfSB-MonatX-Il2KST0BqBc89Hpfp-g-Z6ojtGSFuZTBk-exYetV9pQ1PBxa5xssr_ffy4NWv9itcs8EzTAM2WyvhDIlv9rrpNyDD7OKgUxI2DOQUWNFV2vihXRYgB61AWHzl3GbCMoVcIVe1O9EVfOuPVbFJl4J5UMKoSiHCyZv6bJYICmtkyJ1jtu31O8Lf57WauI1Y4xD7xs8R9DBLv3jzFi2yF-hlWlfG9_juAV2jJkQAVEDCecP0PnjigZDtB7QfPURswRnusLBsbMvOjwIlrkFqiXKRjZgQFZ_6unTJtcL_MTeydt22UKphLIJ4h4UaDMCLqXXdUU6gE3FDWtQ1EVnigTHRUlDi57Cncn8zLrQk8s9tN1OHvkWEUkrZ3bZu-m8LfjQn4PqGZ-UqWXVcJBksXgW7oOtZeke7G__pQfOlFuKCKMVG5q4KZ0CW7av9wtGLftv01aa4yt2XdhocCXMy_O5xwL8xaj2cqD_qlFlbvHZ1apBcDiogwxemwOYcsm8bG3SSad8n3K48-oxSyYE3By0onDzcNIbrPf_1vehD1SkdDubtCtUFDC7GNL9HlyTUTNyo2fV-kn1tSSoj_Jqrei7wTZR_M3RrhrkRCev-Ss7260C0F6iXrUZERO3Af5wfYS-dEyQevjI3hymcRfPT9p7yiRcTR0hrYjJ3pEmh-Mm_XqBdcWu0Xf6KFCHwSRNN9YGW7AWO0JdITQq9hpe_HR9wKtmEeCd5DMAftkh27YbZ1Wy46cMLjQz_BBT9TohN2oc4Y9majI1Qj9AeHSebcAZzel8TKnuQjJtSp7MvYAR7tYCnFtmAmDxE5fGEG7Ou_3sz5i4dCAIFUpZ6Wzn85R-8MRIvQkM92JJo-DGv82NNSqSiNToelW-jQ8Z51nmfUhmFcVJ7KfT-sk9h1XY-9k-IZ14OfbEvc6FQg_vyC8Np3GEk6gW0wwRt1BI6xNvK1tqdCtuA8U4DLcgc6_eBjVL_9TJjrhiPMVzK93Hj7fxHYWEv31eH6dxAUHoPNITL9TR1w1vx-BrLmYp8NWFOxTM0pUXPuLveITECvog3eUOc3HeNhp13gScXaYVCFAx3tBinKBG8eaUKYeD19B1LbbzHuB4dlRpX_Am_11iruQddBwhgdyvrolmsMY5uiYEELeKfQ5k_1tw3nyOA68rIM-CRF-JYPRzjqiyyRQSHr0oNJ0YK9EFeHRis01WqIqWn21fKn_QYLG3poLc7RqByS5-ygxj4GRN9S_h3rhZ1EdNLfP9sxf4ygKC6uvW6qcWgVGNtfG_PSntY5ADNhBg3Dp7dKrjz9pgkfCRZnraaqsiWDaaa_nzAmXSr4a8cgONlZuODrZtLGnJ-gC2PX8os1lqEbdlsEKSUxpC8a7UM3z-53KXJOliZAqBfT_bc24nx-mV-wOYM0J93xfalmj2aa_V1U4un3OrF0f_zDp3dbxsQtwsxJo4QNQZ3OiI4hn3RnGZY3U56AwEjdk92U_1qblIPFhgtzA1C7-wkzLbMKY81nrJqTGP57TFEiu6xINz2axa64IrSD8Q71dESUKkd1-06jt639AXzTxkTZxnMDgVuL03FXgz8tJPmroYj5DAPJ5oIUuf4IzQ1TSO-5vY0CptRGMGj6JS2SYxE8fCVGPa2cQY2bhpeZ7IUjt5YOChGvgR7Cf-LdNDpNRAymD1sNgaUU6AOE71_E4e4ScXvWQvIhvreHanxTQAVeIrYcREmaSNchvLGklqx1jEhbGUc27cVzlfQ3Q7DnW0uuwBqGhccP8SbQCvXwAgIuyHeHzTD4stUEoUps1UhfLtBGlOvuhRl0juwo7BwkrW-iGL7mBdktgYRmXUMEu5WiPwe9TlOtpLFelrWlHoojZYIb9OlkyoPdrCU-AeilaJeGJwtVammesB6WBHYqDMvOa2u5-Sds_3T2_IMCwnPS-xmImqnNVoI6i6P_GYQDbsbdcfm1GfLFxfs52hUmY9Zc2XqYuxukBbxcN8x1M_JfyWSZ7dmStGQAr_liDo70QCTsby_0gp7HEsVjU5aRh6b36mlnFAkoV4LLhFjqGwJ4pDRpmwVyFN2oTETDYxX84f6YN2F3QgXBREoxCYwKGaFiLAPUJvOWecbtXx_od782dNiWuz3IZJsq2EyFYMTOZ90hXtPm6j_wgjjdxG4i5mu77aEIYrylRSj7-mR-rKN7SG3OUBOhJw_8SsZ-uP_iqEWrwrdByxSLdjWVP-G6pMw_dfv_WXqOqrbtqmvGhRR575WxONK2YVL0gKW_jYnQLkfLBR9uylgurty36LQnph15PPHjeoo8BrProGwg-dKPtl1jgduMt-JT0q7e52ctAX7CNatBJamLZRIwgmkMsewI52EaSep0RYmbxXXpPaIECsoilUBtbtYjefm6d1bM4a7eI8saYjQ3WGwWIirsMnEzstYW90n9LVwo8sztY_mUIrfxhzfuN4AkXRyzpwB4xEA6FpiiYRuHmU2inY6p-eMbbha0yWHOyF3hY4Hb9LIjuGzCsT3njIFpVhrHET4a5pHYbkLqeyg5P9oBaUr6I9d2Dkgj-r4P379WNE5zxW5TAxwBwSjqViSNOEvl9rhgPClZ_LyFvTdllKNbpB0AdPaC28d25nbTTdyoBF0ALeyPuXwSgfOSJwMsSco9qA31zvtQjmToSm6Bv8ejxCkpUQWkhsSQfTNhQdvmgSyHKl6nM14h4aSjvSgr14T0rHhlvn7g2z96KeO2-jbvz-dQ8iL-A47NwEMQCgqobsNXvpKsjIWI6mi2dXsBclMjTGpuJj8s4npahRDymvuupj-tJZ5gd_odlYXkUrIZrIkjMVq4Y2D20ZVMgKkMZAkuiYqob6LJfFaN_D0tZTmPnrbuqzIto6jENj0pJB0BB89XA9a4L1aiPlGsxpzORmAfjQtZZoxUiGLw7hfu7kFEBjiWxzzEEnhrg5q_JulelIXIEVQWoGmrrvCw9nq9wAOEhUoLjlLT1xeZmiDoKOtyNjyHCQlKUJGTE1YXbe6zOLq8vr9CQ4bI01SWG18lbbD2uT3-gAAAAAAAAAAAAAAAA4iNEQ";
        
        String[] parts = tokenString.split("\\.");
        if (parts.length < 2 || parts.length > 3) throw new IllegalArgumentException("Parsing error");
        String encodedHeader = parts[0];
        String encodedContent = parts[1];
        String encodedSignatureInput = encodedHeader + '.' + encodedContent;

        System.out.println("EncodedHeader: " + encodedHeader);
        System.out.println("encodedContent: " + encodedContent);
        System.out.println("encodedSignatureInput: " + encodedSignatureInput);
        System.out.println("parts.length: " + parts.length);

        byte[] content = Base64Url.decode(encodedContent);
        if (parts.length > 2) {
            String encodedSignature = parts[2];
            byte[] signature = Base64Url.decode(encodedSignature);
        }
        byte[] headerBytes = Base64Url.decode(encodedHeader);
        System.out.println("headerBytes: " + headerBytes);

        // JWSHeader header = JsonSerialization.readValue(headerBytes, JWSHeader.class);
        ObjectMapper mapper = new ObjectMapper();
        System.out.println("Mapper creado"); 
        mapper.readValue(headerBytes, JWSHeader.class);
        
        System.out.println("Exito");    
    }
}
