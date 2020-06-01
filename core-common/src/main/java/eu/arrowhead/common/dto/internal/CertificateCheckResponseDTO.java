package eu.arrowhead.common.dto.internal;

import java.io.Serializable;
import java.math.BigInteger;

public class CertificateCheckResponseDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private int version;
    private String producedAt;
    private String endOfValidity;
    private String commonName;
    private BigInteger serialNumber;
    private String status;

    public CertificateCheckResponseDTO() {
    }

    public CertificateCheckResponseDTO(int version, String producedAt, String endOfValidity, String commonName, BigInteger serialNumber, String status) {
        this.version = version;
        this.producedAt = producedAt;
        this.endOfValidity = endOfValidity;
        this.commonName = commonName;
        this.serialNumber = serialNumber;
        this.status = status;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public String getProducedAt() {
        return producedAt;
    }

    public void setProducedAt(String producedAt) {
        this.producedAt = producedAt;
    }

    public String getEndOfValidity() {
        return endOfValidity;
    }

    public void setEndOfValidity(String endOfValidity) {
        this.endOfValidity = endOfValidity;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
