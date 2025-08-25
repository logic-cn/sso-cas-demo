package com.example.cassdemo.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "cas")
public class CasProperties {
    private String serverUrlPrefix;
    private String serverLoginUrl;
    private String serverLogoutUrl;
    private String clientHostUrl;
}
