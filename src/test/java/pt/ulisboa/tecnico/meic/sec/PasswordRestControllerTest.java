package pt.ulisboa.tecnico.meic.sec;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class)
@WebAppConfiguration
public class PasswordRestControllerTest {

    private MediaType contentType = new MediaType(MediaType.APPLICATION_JSON.getType(),
            MediaType.APPLICATION_JSON.getSubtype(),
            Charset.forName("utf8"));

    private MockMvc mockMvc;

    private String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmcNA8P0Ywj3ua6jrU22jdPtwrlKX3tdZBQ0R3UlkLuiVWZTWYbTIzKO3ATGt1H7pk0lwrp+cHwpbqhmszW6eAQEVgoHeW5cDiHR7lQ//xXmSumMYm9GeEtQvpI2SdqXMAs9tS5CFbE2IB1rt07vsmeVL4oxYx1617CxL4Qz52XAZWIjVt2aCtzfcP9EvKwnVhxFkyK4pd0d9dTiBABcWXw2qHwXs80rFWbin8cP5I1wtH2DurVizdfcb9RkDbrKOZMqbryQbkE3B5etpYf7PPZNiJT7E/PAz64tk+JLSdF2smGrtga4UAlOVBIWLU6uys0QhibCbAJF3Q3rOZCyy4QIDAQAB";

    private HttpMessageConverter mappingJackson2HttpMessageConverter;

    private User user;

    private List<Password> passwordList = new ArrayList<>();

    @Autowired
    private PasswordRepository passwordRepository;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    void setConverters(HttpMessageConverter<?>[] converters) {

        this.mappingJackson2HttpMessageConverter = Arrays.asList(converters).stream()
                .filter(hmc -> hmc instanceof MappingJackson2HttpMessageConverter)
                .findAny()
                .orElse(null);

        assertNotNull("the JSON message converter must not be null",
                this.mappingJackson2HttpMessageConverter);
    }

    @Before
    public void setup() throws Exception {
        this.mockMvc = webAppContextSetup(webApplicationContext).build();

        this.passwordRepository.deleteAllInBatch();
        this.userRepository.deleteAllInBatch();


        //this.passwordList.add(passwordRepository.save(new Password(user, "http://bookmark.com/1/" + userName, "A description")));
        //this.passwordList.add(passwordRepository.save(new Password(user, "http://bookmark.com/2/" + userName, "A description")));
    }


    @Test
    public void registerUser() throws Exception {
        mockMvc.perform(post("/")
                .content(this.json(new User(
                        publicKey,
                        "IqQbOzafmSrVv7EiBWQhq2BoSj/T3PJnWPpBWp8n6tjU8Xxa2tzC7KQldDVm0urHyfGGlFuNrRAkImqJAMaJu2a+MTYAv4LtUrbaMH6VlFEQ24FXDE/CeIZFhWGNZxjHTHIBDB1BOyNLTP5S+RX41GF8kFPdeCXpLYAE1yjrb2jBIRIt5hYLrmg9KxzZLYYFzqBY7K/rcfSg30T/KtE8NC9ktesYxZp8WGBCCV4DMX69jrRSH8W0pjfPFdpHolaDGxBYfGHuMhqxeNCZ+8AR9tv+hhMLOsPDDkJOVNYM79J1Bzb2Z9BkoX9SABnOia9pr0VyX7oAiQSZa6KRyZTHZw=="
                )))
                .contentType(contentType))
                .andExpect(status().isCreated());
    }

    @Test
    public void registerUserWithBadSignature() throws Exception {
        mockMvc.perform(post("/")
                .content(this.json(new User(
                        publicKey,
                        "dsfJAMaJu2a+MTYAv4LtUrbaMH6VlFEQ24FXDE/CeIZFhWGNZxjHTHIBDB1BOyNLTP5S+RX41GF8kFPdeCXpLYAE1yjrb2jBIRIt5hYLrmg9KxzZLYYFzqBY7K/rcfSg30T/KtE8NC9ktesYxZp8WGBCCV4DMX69jrRSH8W0pjfPFdpHolaDGxBYfGHuMhqxeNCZ+8AR9tv+hhMLOsPDDkJOVNYM79J1Bzb2Z9BkoX9SABnOia9pr0VyX7oAiQSZa6KRyZTHZw=="
                )))
                .contentType(contentType))
                .andExpect(status().isNotAcceptable());
    }

    @Test
    public void createPasswordWithBadReqSignature() throws Exception {
        this.user = userRepository.save(new User("CR1PCxT3BO5QyrExJG/i33khZoS5ReB6yFCzLqYxiQQ="));

        String passwordJson = json(new Password(
                publicKey,
                "eteSCFEAzyrZFmy4We/VFw==",
                "GTlGML/TS68bEmKFr8sm8A==",
                "3qf8BBvCl455lBCeVh00zA==",
                "BR+CZcVc0p11DNGdsmblAzGkpOitEcWSbrrDxslUlP7zTrpe6VWgs7Ywhhk0GcjGHT3Jj9GR8nUb7YGskTZPI85o/pT0kT4T6si0uaIRuGTxWVBRU4h4pWPr4NW07e1pLt/xvm/n0rwe0m2U8YYFEoKA86ZaRdDi26kbcfi3oS17LZVhILgw6JU7RDWIkrkDUKIO8p1OhCaYu3SLmhizH8L1BgAl4KU5O/VEk0GZPH+RDhiN7mSt/rId5Ln4DrXoi3MTBU3Iyrlu6qKHtfgSsIcZC3rhUEpPrnsVwUHW77GO9fJgm5qfQdNWEKMFynxXjMXqktKNSdHMO3jqrn1jpQ==",
                "2017-03-15 16:35:00.386",
                "pukcmZoqMZK7QXxD3ZLbVnH2atsvewTKNk6DIhF0fU0=",
                "badbadbadbad-9d93tibaFSuw01gfNyK/kPc7Jtz3BYYhZU5bMzjjc7iuk/sJqIqICG+IeKbmJr2RmujzZ45L4sRoYM0Jcd/Gxuh6hd3ww4feJe16FcXImmlzLbJFy3KJs2bD7+oE9uBZ3+D3X+2cxQU0rJy2RFj7Zn6+0wYjD91e67kZargZd0MMLjkXu0xrasuUF0mb9+zymMdfCI84wcxDCrL3E4d7d3JLA=="
        ));

        this.mockMvc.perform(put("/password")
                .contentType(contentType)
                .content(passwordJson))
                .andExpect(status().isNotAcceptable());
    }

    @Test
    public void sendWrongTimestamp() throws Exception {
        this.user = userRepository.save(new User("CR1PCxT3BO5QyrExJG/i33khZoS5ReB6yFCzLqYxiQQ="));

        String passwordJson = json(new Password(
                publicKey,
                "eteSCFEAzyrZFmy4We/VFw==",
                "GTlGML/TS68bEmKFr8sm8A==",
                "3qf8BBvCl455lBCeVh00zA==",
                "BR+CZcVc0p11DNGdsmblAzGkpOitEcWSbrrDxslUlP7zTrpe6VWgs7Ywhhk0GcjGHT3Jj9GR8nUb7YGskTZPI85o/pT0kT4T6si0uaIRuGTxWVBRU4h4pWPr4NW07e1pLt/xvm/n0rwe0m2U8YYFEoKA86ZaRdDi26kbcfi3oS17LZVhILgw6JU7RDWIkrkDUKIO8p1OhCaYu3SLmhizH8L1BgAl4KU5O/VEk0GZPH+RDhiN7mSt/rId5Ln4DrXoi3MTBU3Iyrlu6qKHtfgSsIcZC3rhUEpPrnsVwUHW77GO9fJgm5qfQdNWEKMFynxXjMXqktKNSdHMO3jqrn1jpQ==",
                "2017-03-15 16:35:07.386",
                "pukcmZoqMZK7QXxD3ZLbVnH2atsvewTKNk6DIhF0fU0=",
                "NIogO7ypRSJV51hYr/TW+EaUr7nH1hzaFMTvyVoAs5ZptXOnwg5uk+VdNhG79yPL7vkcDxLvsCo0SqygEtzqgPFedT7gHzptWruLmmSE1lxk6+LYgY9RBNZYOaR339d93tibaFSuw01gfNyK/kPc7Jtz3BYYhZU5bMzjjc7iuk/sJqIqICG+IeKbmJr2RmujzZ45L4sRoYM0Jcd/Gxuh6hd3ww4feJe16FcXImmlzLbJFy3KJs2bD7+oE9uBZ3+D3X+2cxQU0rJy2RFj7Zn6+0wYjD91e67kZargZd0MMLjkXu0xrasuUF0mb9+zymMdfCI84wcxDCrL3E4d7d3JLA=="
        ));

        this.mockMvc.perform(put("/password")
                .contentType(contentType)
                .content(passwordJson))
                .andExpect(status().isNotAcceptable());
    }

    /*@Test
    public void readSingleBookmark() throws Exception {
        mockMvc.perform(get("/" + userName + "/bookmarks/"
                + this.passwordList.get(0).getId()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(contentType))
                .andExpect(jsonPath("$.id", is(this.passwordList.get(0).getId().intValue())))
                .andExpect(jsonPath("$.uri", is("http://bookmark.com/1/" + userName)))
                .andExpect(jsonPath("$.description", is("A description")));
    }

    @Test
    public void readBookmarks() throws Exception {
        mockMvc.perform(get("/" + userName + "/bookmarks"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(contentType))
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[0].id", is(this.passwordList.get(0).getId().intValue())))
                .andExpect(jsonPath("$[0].uri", is("http://bookmark.com/1/" + userName)))
                .andExpect(jsonPath("$[0].description", is("A description")))
                .andExpect(jsonPath("$[1].id", is(this.passwordList.get(1).getId().intValue())))
                .andExpect(jsonPath("$[1].uri", is("http://bookmark.com/2/" + userName)))
                .andExpect(jsonPath("$[1].description", is("A description")));
    }

    @Test
    public void createBookmark() throws Exception {
        String bookmarkJson = json(new Password(
                this.user, "http://spring.io", "a bookmark to the best resource for Spring news and information"));

        this.mockMvc.perform(post("/" + userName + "/bookmarks")
                .contentType(contentType)
                .content(bookmarkJson))
                .andExpect(status().isCreated());
    }*/

    protected String json(Object o) throws IOException {
        MockHttpOutputMessage mockHttpOutputMessage = new MockHttpOutputMessage();
        this.mappingJackson2HttpMessageConverter.write(
                o, MediaType.APPLICATION_JSON, mockHttpOutputMessage);
        return mockHttpOutputMessage.getBodyAsString();
    }
}
