package com.dh.cert;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class TrustStoreMeter {
    private final String trustStorePath;
    private final String trustStorePwd;
    private final MeterRegistry registry;
    private Logger logger = LoggerFactory.getLogger("certAppLogger");

    public TrustStoreMeter(@Value("${javax.net.ssl.trustStore}") String trustStorePath,
                           @Value("${javax.net.ssl.trustStorePassword}") String trustStorePwd,
                           @Autowired MeterRegistry registry) {
        this.trustStorePath = trustStorePath;
        this.trustStorePwd = trustStorePwd;
        this.registry = registry;
    }

    @PostConstruct
    public void registerTrustStoreMeter() throws GeneralSecurityException, IOException {
        var trustStore = trustStore(trustStorePath, trustStorePwd);
        var aliases = trustStore.aliases().asIterator();

        while (aliases.hasNext()) {
            var nextAlias = aliases.next();
            var cert = (X509Certificate) trustStore.getCertificate(nextAlias);
            var startDate = cert.getNotBefore();
            var endDate = cert.getNotAfter();
            long diffInMillies = endDate.getTime() - startDate.getTime();
            long diffInDays = TimeUnit.DAYS.convert(diffInMillies, TimeUnit.MILLISECONDS);
            var tags = Tags.of(
                Tag.of("validity.period.days", String.valueOf(diffInDays)),
                Tag.of("validity.date.start", startDate.toString()),
                Tag.of("validity.date.end", endDate.toString())
            );

            Gauge.builder(
                "truststore." + nextAlias,
                    () -> {
                        long secondsLeft = endDate.getTime() - LocalDate.now().atStartOfDay().toEpochSecond(ZoneOffset.UTC) * 1000;
                        return new AtomicLong(TimeUnit.DAYS.convert(secondsLeft, TimeUnit.MILLISECONDS));
                    })
                .baseUnit("days")
                .description("Days left until certificate expires")
                .tags(tags)
                .register(registry);

            logger.info("Metric \"truststore.{}\" registered", nextAlias);
        }
    }

    private KeyStore trustStore(String trustStorePath, String trustStorePwd) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] pwd = trustStorePwd.toCharArray();
        try (FileInputStream fis = new FileInputStream(trustStorePath)) {
            ks.load(fis, pwd);
        }
        return ks;
    }
}


