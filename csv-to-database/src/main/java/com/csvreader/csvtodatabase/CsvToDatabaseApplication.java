package com.csvreader.csvtodatabase;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan()
public class CsvToDatabaseApplication {

	public static void main(String[] args) {
		SpringApplication.run(CsvToDatabaseApplication.class, args);
	}

}
