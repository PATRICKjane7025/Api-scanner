jtags = {
    "Apache Struts": {
        "versions": ["<2.5.20"],
        "vulnerability": "Remote Code Execution (RCE)",
        "notes": "Known for RCE vulnerabilities."
    },
    "Spring Framework": {
        "versions": ["<5.2.0", "<4.3.30"],
        "vulnerability": "Insecure Deserialization",
        "notes": "Vulnerabilities related to RCE through deserialization."
    },
    "Hibernate": {
        "versions": ["<5.4.27"],
        "vulnerability": "SQL Injection",
        "notes": "Vulnerabilities in query processing."
    },
    "Jackson": {
        "versions": ["<2.9.10"],
        "vulnerability": "Remote Code Execution",
        "notes": "Older versions have deserialization vulnerabilities."
    },
    "Apache Commons Collections": {
        "versions": ["<3.2.2"],
        "vulnerability": "Remote Code Execution",
        "notes": "Exploitable via gadgets in deserialization."
    },
    "Apache Tomcat": {
        "versions": ["<9.0.31", "<8.5.55"],
        "vulnerability": "Information Disclosure",
        "notes": "Various issues including file inclusion vulnerabilities."
    },
    "Log4j": {
        "versions": ["<2.15.0"],
        "vulnerability": "Remote Code Execution (Log4Shell)",
        "notes": "Critical RCE vulnerability."
    },
    "JUnit": {
        "versions": ["<4.12"],
        "vulnerability": "Insecure Usage of External Libraries",
        "notes": "Potential for RCE in test configurations."
    },
    "Apache POI": {
        "versions": ["<3.15"],
        "vulnerability": "XML External Entity (XXE) Injection",
        "notes": "Can lead to sensitive data disclosure."
    },
    "Apache Velocity": {
        "versions": ["<1.7"],
        "vulnerability": "Template Injection",
        "notes": "Vulnerabilities in template processing."
    },
    "Bouncy Castle": {
        "versions": ["<1.61"],
        "vulnerability": "Cryptographic Issues",
        "notes": "Known for various cryptographic vulnerabilities."
    },
    "Apache PDFBox": {
        "versions": ["<2.0.20"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerabilities that can lead to resource exhaustion."
    },
    "Apache Camel": {
        "versions": ["<2.22.1"],
        "vulnerability": "Information Disclosure",
        "notes": "Vulnerabilities related to data handling."
    },
    "JasperReports": {
        "versions": ["<6.3.1"],
        "vulnerability": "XML Injection",
        "notes": "Can allow unauthorized access to data."
    },
    "Jersey": {
        "versions": ["<2.25"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerabilities related to resource exhaustion."
    },
    "Grails": {
        "versions": ["<3.3.10"],
        "vulnerability": "Code Injection",
        "notes": "Potential for RCE through injection attacks."
    },
    "Groovy": {
        "versions": ["<2.4.16"],
        "vulnerability": "Insecure Deserialization",
        "notes": "Deserialization issues that could lead to RCE."
    },
    "Spring Security": {
        "versions": ["<4.2.4"],
        "vulnerability": "Insecure Configuration",
        "notes": "Potential security misconfigurations."
    },
    "Apache Shiro": {
        "versions": ["<1.4.2"],
        "vulnerability": "Session Fixation",
        "notes": "Can lead to session hijacking."
    },
    "Apache Ant": {
        "versions": ["<1.9.7"],
        "vulnerability": "Code Execution",
        "notes": "Vulnerabilities in task execution."
    },
    "JDK (Java Development Kit)": {
        "versions": ["<8u161", "<7u181"],
        "vulnerability": "Multiple Security Issues",
        "notes": "Older versions have critical vulnerabilities."
    },
    "JavaMail": {
        "versions": ["<1.6.2"],
        "vulnerability": "Denial of Service",
        "notes": "Potentially vulnerable to resource exhaustion."
    },
    "JNDI (Java Naming and Directory Interface)": {
        "versions": ["<1.3"],
        "vulnerability": "Remote Code Execution",
        "notes": "Exploitable through LDAP injections."
    },
    "Jersey 2.x": {
        "versions": ["<2.31"],
        "vulnerability": "Information Disclosure",
        "notes": "Exposes sensitive information through error messages."
    },
    "Spring Web Flow": {
        "versions": ["<2.5"],
        "vulnerability": "Cross-Site Scripting (XSS)",
        "notes": "Can be vulnerable to XSS attacks."
    },
    "Apache Commons FileUpload": {
        "versions": ["<1.3.3"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerable to resource exhaustion through file uploads."
    },
    "Apache Commons IO": {
        "versions": ["<2.6"],
        "vulnerability": "Path Traversal",
        "notes": "Can lead to unauthorized file access."
    },
    "AspectJ": {
        "versions": ["<1.8.9"],
        "vulnerability": "Injection Attacks",
        "notes": "Potential for various code injection vulnerabilities."
    },
    "C3P0": {
        "versions": ["<0.9.5.5"],
        "vulnerability": "SQL Injection",
        "notes": "Can be exploited through incorrect configuration."
    },
    "JDOM": {
        "versions": ["<2.0.6"],
        "vulnerability": "XML External Entity (XXE) Injection",
        "notes": "Vulnerable to XML entity attacks."
    },
    "OkHttp": {
        "versions": ["<3.12.1"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerable to DoS through specific payloads."
    },
    "JAXB": {
        "versions": ["<2.2.6"],
        "vulnerability": "Insecure Deserialization",
        "notes": "Vulnerable to deserialization attacks."
    },
    "JUnit": {
        "versions": ["<5.0"],
        "vulnerability": "Test Execution Vulnerabilities",
        "notes": "Old test frameworks can lead to RCE."
    },
    "JSP (JavaServer Pages)": {
        "versions": ["<2.3"],
        "vulnerability": "Cross-Site Scripting (XSS)",
        "notes": "Vulnerabilities in page rendering."
    },
    "Apache Spark": {
        "versions": ["<2.4.6"],
        "vulnerability": "Data Exposure",
        "notes": "Potential data leaks in older versions."
    },
    "Apache Flink": {
        "versions": ["<1.8.0"],
        "vulnerability": "Data Exposure",
        "notes": "Can expose sensitive information."
    },
    "Jetty": {
        "versions": ["<9.4.22"],
        "vulnerability": "Information Disclosure",
        "notes": "Known for various security vulnerabilities."
    },
    "Apache ActiveMQ": {
        "versions": ["<5.15.10"],
        "vulnerability": "Remote Code Execution",
        "notes": "Vulnerabilities in message processing."
    },
    "Apache Camel": {
        "versions": ["<2.20"],
        "vulnerability": "Information Disclosure",
        "notes": "Vulnerable to information leakage."
    },
    "Apache Ignite": {
        "versions": ["<2.6.0"],
        "vulnerability": "Data Exposure",
        "notes": "Potential data leaks in cluster configurations."
    },
    "Ehcache": {
        "versions": ["<2.10.6"],
        "vulnerability": "Insecure Caching",
        "notes": "Potential data leakage through misconfigured cache."
    },
    "Apache CXF": {
        "versions": ["<3.2.1"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerable to resource exhaustion attacks."
    },
    "Gson": {
        "versions": ["<2.8.6"],
        "vulnerability": "Insecure Deserialization",
        "notes": "Vulnerable to attacks through deserialization."
    },
    "Retrofit": {
        "versions": ["<2.4.0"],
        "vulnerability": "Insecure Communication",
        "notes": "Older versions may have insecure HTTPS implementations."
    },
    "Apache Cordova": {
        "versions": ["<8.0.0"],
        "vulnerability": "Insecure Web Views",
        "notes": "Potential for content injection."
    },
    "Android SDK": {
        "versions": ["<28.0.3"],
        "vulnerability": "Multiple Vulnerabilities",
        "notes": "Older versions have various security issues."
    },
    "Apache Kafka": {
        "versions": ["<2.1.1"],
        "vulnerability": "Denial of Service",
        "notes": "Known for performance issues under load."
    },
    "Jersey Client": {
        "versions": ["<2.28"],
        "vulnerability": "Information Disclosure",
        "notes": "Sensitive data can be leaked through error handling."
    },
    "Apache Hadoop": {
        "versions": ["<3.2.0"],
        "vulnerability": "Multiple Vulnerabilities",
        "notes": "Known for security issues in distributed systems."
    },
    "Apache Beam": {
        "versions": ["<2.4.0"],
        "vulnerability": "Data Exposure",
        "notes": "Potential data leaks through misconfigured pipelines."
    },
    "jQuery": {
        "versions": ["<3.0.0"],
        "vulnerability": "Cross-Site Scripting (XSS)",
        "notes": "Older versions are prone to XSS."
    },
    "JGroups": {
        "versions": ["<3.6.16"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerable to specific payload attacks."
    },
    "Apache Commons Lang": {
        "versions": ["<3.8"],
        "vulnerability": "Denial of Service",
        "notes": "Potential issues with certain string operations."
    },
    "XStream": {
        "versions": ["<1.4.10"],
        "vulnerability": "Insecure Deserialization",
        "notes": "Known for deserialization vulnerabilities."
    },
    "Apache PDFBox": {
        "versions": ["<2.0.0"],
        "vulnerability": "Denial of Service",
        "notes": "Can lead to resource exhaustion."
    },
    "Zookeeper": {
        "versions": ["<3.4.10"],
        "vulnerability": "Authentication Bypass",
        "notes": "Known for various vulnerabilities."
    },
    "Apache Camel": {
        "versions": ["<2.12.0"],
        "vulnerability": "Information Disclosure",
        "notes": "Exposes sensitive information."
    },
    "Thymeleaf": {
        "versions": ["<3.0.10"],
        "vulnerability": "Cross-Site Scripting (XSS)",
        "notes": "Vulnerabilities in template rendering."
    },
    "Jasypt": {
        "versions": ["<1.9.0"],
        "vulnerability": "Cryptographic Issues",
        "notes": "Vulnerable to specific attack vectors."
    },
    "JOOQ": {
        "versions": ["<3.9.0"],
        "vulnerability": "SQL Injection",
        "notes": "Older versions can be misconfigured leading to injection."
    },
    "Apache Lucene": {
        "versions": ["<7.0.0"],
        "vulnerability": "Information Disclosure",
        "notes": "Can expose sensitive information."
    },
    "Vert.x": {
        "versions": ["<3.5.0"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerable to specific payloads."
    },
    "Apache Tika": {
        "versions": ["<1.17"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerabilities in content detection."
    },
    "JUnit": {
        "versions": ["<4.13"],
        "vulnerability": "Insecure Test Cases",
        "notes": "Old test cases can lead to vulnerabilities."
    },
    "Apache OpenNLP": {
        "versions": ["<1.9.1"],
        "vulnerability": "Information Exposure",
        "notes": "Can leak sensitive information during processing."
    },
    "Cassandra": {
        "versions": ["<3.11.0"],
        "vulnerability": "Multiple Vulnerabilities",
        "notes": "Various security issues in data handling."
    },
    "JPA (Java Persistence API)": {
        "versions": ["<2.1"],
        "vulnerability": "SQL Injection",
        "notes": "Older versions are prone to injection vulnerabilities."
    },
    "Apache CouchDB": {
        "versions": ["<2.0.0"],
        "vulnerability": "Multiple Vulnerabilities",
        "notes": "Known for various security issues."
    },
    "Resteasy": {
        "versions": ["<3.0.0"],
        "vulnerability": "Denial of Service",
        "notes": "Potential resource exhaustion vulnerabilities."
    },
    "Apache Zeppelin": {
        "versions": ["<0.8.0"],
        "vulnerability": "Information Disclosure",
        "notes": "Sensitive information can be exposed."
    },
    "Apache Airflow": {
        "versions": ["<1.10.0"],
        "vulnerability": "Information Disclosure",
        "notes": "Vulnerable to exposure of sensitive data."
    },
    "Quartz": {
        "versions": ["<2.3.0"],
        "vulnerability": "Denial of Service",
        "notes": "Can be exploited under specific conditions."
    },
    "Apache Solr": {
        "versions": ["<6.6.0"],
        "vulnerability": "Information Exposure",
        "notes": "Potential for data leakage."
    },
    "Java Servlet API": {
        "versions": ["<3.1"],
        "vulnerability": "Multiple Vulnerabilities",
        "notes": "Older versions have various security issues."
    },
    "Jython": {
        "versions": ["<2.7.2"],
        "vulnerability": "Insecure Usage of External Libraries",
        "notes": "Potential RCE in old scripts."
    },
    "AspectJ": {
        "versions": ["<1.9.0"],
        "vulnerability": "Injection Attacks",
        "notes": "Known for potential vulnerabilities."
    },
    "JASPIC (Java Authentication SPI for Containers)": {
        "versions": ["<1.0"],
        "vulnerability": "Authentication Bypass",
        "notes": "Can lead to unauthorized access."
    },
    "Jetty": {
        "versions": ["<9.4.0"],
        "vulnerability": "Information Disclosure",
        "notes": "Exposed sensitive information."
    },
    "Logback": {
        "versions": ["<1.2.3"],
        "vulnerability": "Denial of Service",
        "notes": "Can lead to resource exhaustion."
    },
    "JMX (Java Management Extensions)": {
        "versions": ["<1.3"],
        "vulnerability": "Remote Code Execution",
        "notes": "Exploitable through misconfigurations."
    },
    "Java Server Faces (JSF)": {
        "versions": ["<2.2"],
        "vulnerability": "Cross-Site Scripting (XSS)",
        "notes": "Vulnerabilities in component rendering."
    },
    "Java XML Digital Signature": {
        "versions": ["<1.0.5"],
        "vulnerability": "Signature Forgery",
        "notes": "Can be exploited to forge signatures."
    },
    "Apache TomEE": {
        "versions": ["<1.7.0"],
        "vulnerability": "Multiple Vulnerabilities",
        "notes": "Known for various security issues."
    },
    "Ceylon": {
        "versions": ["<1.3.3"],
        "vulnerability": "Insecure Usage of Libraries",
        "notes": "Potential for code injection."
    },
    "Java WebSocket API": {
        "versions": ["<1.0"],
        "vulnerability": "Denial of Service",
        "notes": "Can lead to resource exhaustion."
    },
    "Netty": {
        "versions": ["<4.1.30"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerable to specific payloads."
    },
    "RxJava": {
        "versions": ["<1.3"],
        "vulnerability": "Multiple Vulnerabilities",
        "notes": "Potential for various security issues."
    },
    "Apache Camel": {
        "versions": ["<2.16.0"],
        "vulnerability": "Information Disclosure",
        "notes": "Exposes sensitive information."
    },
    "Spring Batch": {
        "versions": ["<4.0.0"],
        "vulnerability": "Insecure Job Configuration",
        "notes": "Can be vulnerable to misconfigurations."
    },
    "JasperReports": {
        "versions": ["<6.7.0"],
        "vulnerability": "Code Injection",
        "notes": "Potential RCE through template configurations."
    },
    "JavaMail API": {
        "versions": ["<1.6.0"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerable to resource exhaustion."
    },
    "JPA (Java Persistence API)": {
        "versions": ["<2.0"],
        "vulnerability": "SQL Injection",
        "notes": "Older versions are prone to injection vulnerabilities."
    },
    "Apache HBase": {
        "versions": ["<2.0.0"],
        "vulnerability": "Information Exposure",
        "notes": "Can expose sensitive information."
    },
    "Apache Geode": {
        "versions": ["<1.4.0"],
        "vulnerability": "Denial of Service",
        "notes": "Vulnerabilities related to resource management."
    },
    "Apache Arrow": {
        "versions": ["<0.8.0"],
        "vulnerability": "Data Exposure",
        "notes": "Potential for information leakage."
    },
    "JavaFX": {
        "versions": ["<11"],
        "vulnerability": "Multiple Vulnerabilities",
        "notes": "Older versions have various security issues."
    },
    "Spring Cloud": {
        "versions": ["<2.0.0"],
        "vulnerability": "Insecure Configuration",
        "notes": "Potential for security misconfigurations."
    },
    "Apache Lucene": {
        "versions": ["<8.0.0"],
        "vulnerability": "Information Exposure",
        "notes": "Known for potential data leaks."
    },
}

