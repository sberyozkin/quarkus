package io.quarkus.tls.cli;

import io.quarkus.tls.cli.letsencrypt.LetsEncryptPrepareCommand;
import picocli.CommandLine;

@CommandLine.Command(name = "lets-encrypt", sortOptions = false, header = "Prepare, generate and renew Let's Encrypt Certificates", subcommands = {
        LetsEncryptPrepareCommand.class,
        //        LetsEncryptGenerateCommand.class,
        //        LetsEncryptRenewCommand.class,
})
public class LetsEncryptCommand {

}
