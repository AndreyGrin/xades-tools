<?php
declare(strict_types=1);

namespace XadesTools;

use DomDocument;
use DOMException;
use XadesTools\Exception\XadesException;

use function base64_encode;
use function basename;
use function chunk_split;
use function date;
use function file_get_contents;
use function openssl_sign;
use function pathinfo;
use function strtolower;
use function strtoupper;
use function trim;

use const PATHINFO_EXTENSION;

class Signature
{
    public const EMBED_BASE_64 = 'base64';
    public const EMBED_IMPORT = 'import';

    protected Certificate $certificate;

    /**
     * For XML files/content canonicalization is required
     * @var bool
     */
    private bool $c14n;
    private string|false $embed = false;

    /**
     * @var null|string Filename for external signature
     */
    private ?string $fileName;

    public function __construct(Certificate $certificate)
    {
        $this->certificate = $certificate;
    }

    public function setEmbed(string|false $embed = self::EMBED_IMPORT): void
    {
        $this->embed = $embed;
    }

    /**
     * @param  string  $content
     * @param  string  $extension
     * @return string
     * @throws DOMException
     */
    public function signXml(string $content, string $extension = 'xml'): string
    {
        $this->c14n = true;
        $this->fileName = 'file.' . $extension;
        return $this->sign($content);
    }

    /**
     * @param string $filePath
     * @return string
     * @throws XadesException
     * @throws DOMException
     */
    public function signFile(string $filePath): string
    {
        $this->fileName = basename($filePath);
        $this->c14n = strtolower(pathinfo($filePath, PATHINFO_EXTENSION)) === 'xml';
        if ($this->c14n && !$this->embed) {
            $xml = new DomDocument();
            $xml->load($filePath);
            $content = $xml->C14n();
        } else {
            $content = file_get_contents($filePath);
        }
        return $this->sign($content);
    }

    /**
     * @param $content
     * @param  bool  $wrapSignatures
     * @return string
     * @throws DOMException
     */
    private function sign($content): string
    {
        /**
         * References between nodes
         */
        $ids = [];
        $digest1 = base64_encode(Tools::sha256($content));

        $dom = new DOMDocument('1.0', 'UTF-8');

        $signature = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Signature');
        $dom->appendChild($signature);

        $signature->setAttribute('Id', $ids['signature'] = Tools::guid());

        $signedInfo = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:SignedInfo');
        $signature->appendChild($signedInfo);

        $canonicalizationMethod = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:CanonicalizationMethod');
        $canonicalizationMethod->setAttribute('Algorithm', Tools::ALGORITHM_EXCLUSIVE_XML_CANONICALIZATION_WITH_COMMENTS);
        $signedInfo->appendChild($canonicalizationMethod);

        $signatureMethod = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:SignatureMethod');
        $signatureMethod->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        $signedInfo->appendChild($signatureMethod);

        $reference1 = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Reference');
        $reference1->setAttribute('Id', "r-{$ids['signature']}-1");

        $signedInfo->appendChild($reference1);

        if ($this->c14n || $this->embed) {
            $transforms = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transforms');
            $transform = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transform');
            $transform->setAttribute('Algorithm', Tools::ALGORITHM_EXCLUSIVE_XML_CANONICALIZATION);
            $transformSignature = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transform');
            $transformSignature->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
            $transformSignature->appendChild(
                $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:XPath', 'not(ancestor-or-self::ds:Signature)')
            );
            $transforms->appendChild($transformSignature);
            $transforms->appendChild($transform);
            $reference1->appendChild($transforms);
        }

        if ($this->embed) {
            $reference1->setAttribute('URI', "");
        } else {
            $objectEmbed = null;
            $reference1->setAttribute('URI', $this->fileName);
        }

        $digestMethod = $dom->createElementNS(Tools::NAMESPACE_DS, 'DigestMethod');
        $digestMethod->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmlenc#sha256");
        $reference1->appendChild($digestMethod);
        $reference1->appendChild($dom->createElementNS(Tools::NAMESPACE_DS, 'DigestValue', $digest1));

        $reference2 = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Reference');
        $reference2->setAttribute('Type', Tools::TYPE_SIGNED_PROPERTIES);
        $reference2->setAttribute('URI', '#ICB_PL-xades-' . $ids['signature']);

        if ($this->c14n || $this->embed) {
            $transforms = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transforms');
            $reference2->appendChild($transforms);
            $transform = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transform');
            $transform->setAttribute('Algorithm', Tools::ALGORITHM_EXCLUSIVE_XML_CANONICALIZATION_WITH_COMMENTS);
            $transforms->appendChild($transform);
        }

        $signedInfo->appendChild($reference2);

        $digestMethod2 = $dom->createElementNS(Tools::NAMESPACE_DS, 'DigestMethod');
        $digestMethod2->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmlenc#sha256");
        $reference2->appendChild($digestMethod2);

        $signatureValue = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:SignatureValue');
        $signatureValue->setAttribute('Id', 'value-' . $ids['signature']);
        if ($objectEmbed) {
            $signature->insertBefore($signatureValue, $objectEmbed);
        } else {
            $signature->appendChild($signatureValue);
        }

        $keyInfo = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:KeyInfo');
        if ($objectEmbed) {
            $signature->insertBefore($keyInfo, $objectEmbed);
        } else {
            $signature->appendChild($keyInfo);
        }

        $x509data = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:X509Data');
        $keyInfo->appendChild($x509data);
        $x509data->appendChild(
            $dom->createElementNS(
                Tools::NAMESPACE_DS,
                'ds:X509Certificate',
                str_replace(PHP_EOL, '', $this->certificate->getCertificate())
            )
        );

        $object = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Object');
        if ($objectEmbed) {
            $signature->insertBefore($object, $objectEmbed);
        } else {
            $signature->appendChild($object);
        }

        $qualifyingProperties = $dom->createElementNS(
            Tools::NAMESPACE_XADES, 'xades:QualifyingProperties'
        );
        $qualifyingProperties->setAttribute('Target', "#" . $ids['signature']);
        $object->appendChild($qualifyingProperties);

        $signedProperties = $dom->createElementNS(Tools::NAMESPACE_XADES, 'xades:SignedProperties');
        $signedProperties->setAttribute('Id', "ICB_PL-xades-{$ids['signature']}");
        $qualifyingProperties->appendChild($signedProperties);

        $signedSignatureProperties = $dom->createelementNS(
            Tools::NAMESPACE_XADES, 'xades:SignedSignatureProperties'
        );
        $signedProperties->appendChild($signedSignatureProperties);

        $signedSignatureProperties->appendChild(
            $dom->createelementNS(
                Tools::NAMESPACE_XADES,
                'xades:SigningTime',
                date(Tools::DATE_FORMAT)
            )
        );

        $signingCertificate = $signedSignatureProperties->appendChild(
            $dom->createelementNS(
                Tools::NAMESPACE_XADES,
                'xades:SigningCertificate'
            )
        );
        $certNode = $signingCertificate->appendChild(
            $dom->createelementNS(
                Tools::NAMESPACE_XADES,
                'xades:Cert'
            )
        );

        $certDigest = $dom->createelementNS(
            Tools::NAMESPACE_XADES,
            'xades:CertDigest'
        );

        $digestMethod = $dom->createelementNS(
            Tools::NAMESPACE_DS,
            'ds:DigestMethod'
        );

        $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');

        $certDigest->appendChild($digestMethod);

        $mime = $dom->createelementNS(
            Tools::NAMESPACE_XADES,
            'xades:MimeType',
            'application/octet-stream'
        );

        $dataObjectFormat = $dom->createelementNS(
            Tools::NAMESPACE_XADES,
            'xades:DataObjectFormat'
        );

        $dataObjectFormat->appendChild($mime);

        $dataObjectFormat->setAttribute('ObjectReference', "r-{$ids['signature']}-1");

        $signedDataObjectProperties = $dom->createElementNS(
            Tools::NAMESPACE_XADES,
            'xades:SignedDataObjectProperties'
        );

        $signedDataObjectProperties->appendChild($dataObjectFormat);

        $signedProperties->appendChild($signedDataObjectProperties);

        $signedPropertiesToDigest = $signedProperties->C14N(exclusive: true, withComments: true);

        $digestValue = $dom->createelementNS(
            Tools::NAMESPACE_DS,
            'ds:DigestValue',
            base64_encode(Tools::sha256($signedPropertiesToDigest))
        );

        $certDigest->appendChild($digestValue);

        $certNode->appendChild($certDigest);

        $issuerSerial = $certNode->appendChild(
            $dom->createelementNS(
                Tools::NAMESPACE_XADES,
                'xades:IssuerSerial'
            )
        );

        $certIssuer = $this->certificate->getCertificateInfo()['issuer'];

        $issuerSerial->appendChild(
            $dom->createelementNS(
                Tools::NAMESPACE_XADES,
                'xades:X509IssuerName',
                "CN={$certIssuer['CN']},OU={$certIssuer['OU']},O={$certIssuer['O']},C={$certIssuer['C']}"
            )
        );

        $issuerSerial->appendChild(
            $dom->createelementNS(
                Tools::NAMESPACE_XADES,
                'xades:X509SerialNumber',
                $this->certificate->getCertificateInfo()['serialNumber']
            )
        );

        $xmlDigest = base64_encode(Tools::sha256($signedPropertiesToDigest));
        $reference2->appendChild($dom->createElementNS(Tools::NAMESPACE_DS, 'DigestValue', $xmlDigest));

        $actualDigest = '';
        openssl_sign(
            $signedInfo->C14N(true, true),
            $actualDigest,
            $this->certificate->getPrivateKey(),
            'sha256WithRSAEncryption'
        );

        $signatureValue->textContent = base64_encode($actualDigest);

        if ($signed = $dom->saveXML()) {
            return $signed;
        } else {
            throw new XadesException();
        }
    }
}
