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
        $signedInfo->setAttribute('Id', Tools::guid());
        $signature->appendChild($signedInfo);

        $canonicalizationMethod = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:CanonicalizationMethod');
        $canonicalizationMethod->setAttribute('Algorithm', Tools::ALGORITHM_EXCLUSIVE_XML_CANONICALIZATION);
        $signedInfo->appendChild($canonicalizationMethod);

        $signatureMethod = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:SignatureMethod');
        $signatureMethod->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        $signedInfo->appendChild($signatureMethod);

        $reference1 = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Reference');
        $reference1->setAttribute('Id', $ids['reference1'] = Tools::guid());

        $signedInfo->appendChild($reference1);

        if ($this->c14n || $this->embed) {
            $transforms = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transforms');
            $reference1->appendChild($transforms);
            $transform = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transform');
            $transform->setAttribute('Algorithm', Tools::ALGORITHM_EXCLUSIVE_XML_CANONICALIZATION);
            $transforms->appendChild($transform);
        }

        if ($this->embed) {

            if ($this->embed === self::EMBED_BASE_64) {
                $objectEmbed = $dom->createElementNS(
                    Tools::NAMESPACE_DS,
                    'ds:Object',
                    trim(
                        chunk_split(
                            base64_encode($content),
                            64,
                            "\n"
                        )
                    )
                );
            } else {
                $objectEmbed = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Object');

                $contentDocument = new \DOMDocument();
                $contentDocument->loadXML($content);

                $newNode = $dom->importNode($contentDocument->documentElement, true);
                $objectEmbed->appendChild($newNode);
            }

            $signature->appendChild($objectEmbed);
            $objectEmbed->setAttribute('Encoding', Tools::ENCODING_BASE64);
            $objectEmbed->setAttribute('Id', $ids['embedded_object'] = Tools::guid());
            $objectEmbed->setAttribute('MimeType', $this->c14n ? 'text/plain' : 'application/octet-stream');

            $digest1 = base64_encode(Tools::sha256($objectEmbed->C14N()));

            $reference1->setAttribute('URI', "#" . $ids['embedded_object']);
        } else {
            $objectEmbed = null;
            $reference1->setAttribute('URI', $this->fileName);
        }

        $digestMethod = $dom->createElementNS(Tools::NAMESPACE_DS, 'DigestMethod');
        $digestMethod->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmlenc#sha256");
        $reference1->appendChild($digestMethod);
        $reference1->appendChild($dom->createElementNS(Tools::NAMESPACE_DS, 'DigestValue', $digest1));

        $reference2 = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Reference');
        $reference2->setAttribute('Id', Tools::guid());

        if ($this->c14n || $this->embed) {
            $transforms = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transforms');
            $reference2->appendChild($transforms);
            $transform = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transform');
            $transform->setAttribute('Algorithm', Tools::ALGORITHM_EXCLUSIVE_XML_CANONICALIZATION);
            $transforms->appendChild($transform);
        }

        $reference2->setAttribute('Type', Tools::TYPE_SIGNED_PROPERTIES);
        $signedInfo->appendChild($reference2);

        $digestMethod2 = $dom->createElementNS(Tools::NAMESPACE_DS, 'DigestMethod');
        $digestMethod2->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmlenc#sha256");
        $reference2->appendChild($digestMethod2);

        $reference3 = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Reference');
        $reference3->setAttribute('Id', Tools::guid());

        if ($this->c14n || $this->embed) {
            $transforms = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transforms');
            $reference3->appendChild($transforms);
            $transform = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Transform');
            $transform->setAttribute('Algorithm', Tools::ALGORITHM_EXCLUSIVE_XML_CANONICALIZATION);
            $transforms->appendChild($transform);
        }

        $reference3->setAttribute('Type', Tools::TYPE_KEY_INFO);
        $signedInfo->appendChild($reference3);

        $digestMethod3 = $dom->createElementNS(Tools::NAMESPACE_DS, 'DigestMethod');
        $digestMethod3->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmlenc#sha256");
        $reference3->appendChild($digestMethod3);

        $signatureValue = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:SignatureValue');
        $signatureValue->setAttribute('Id', Tools::guid());
        if ($objectEmbed) {
            $signature->insertBefore($signatureValue, $objectEmbed);
        } else {
            $signature->appendChild($signatureValue);
        }

        $keyInfo = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:KeyInfo');
        $keyInfo->setAttribute('Id', $ids['key_info'] = Tools::guid());
        if ($objectEmbed) {
            $signature->insertBefore($keyInfo, $objectEmbed);
        } else {
            $signature->appendChild($keyInfo);
        }

        $reference3->setAttribute('URI', "#" . $ids['key_info']);

        $x509data = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:X509Data');
        $keyInfo->appendChild($x509data);
        $x509data->appendChild(
            $dom->createElementNS(
                Tools::NAMESPACE_DS,
                'ds:X509Certificate',
                $this->certificate->getCertificate()
            )
        );

        $keyInfoToDigest = $keyInfo->C14N();
        $xmlDigest = base64_encode(Tools::sha256($keyInfoToDigest));
        $reference3->appendChild($dom->createElementNS(Tools::NAMESPACE_DS, 'DigestValue', $xmlDigest));

        $object = $dom->createElementNS(Tools::NAMESPACE_DS, 'ds:Object');
        if ($objectEmbed) {
            $signature->insertBefore($object, $objectEmbed);
        } else {
            $signature->appendChild($object);
        }

        $qualifyingProperties = $dom->createElementNS(
            Tools::NAMESPACE_XADES, 'xades:QualifyingProperties'
        );
        $qualifyingProperties->setAttribute('Id', Tools::guid());
        $qualifyingProperties->setAttribute('Target', "#" . $ids['signature']);
        $object->appendChild($qualifyingProperties);

        $signedProperties = $dom->createElementNS(Tools::NAMESPACE_XADES, 'xades:SignedProperties');
        $signedProperties->setAttribute('Id', $ids['signed_properties'] = Tools::guid());
        $qualifyingProperties->appendChild($signedProperties);

        $reference2->setAttribute('URI', "#" . $ids['signed_properties']);

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

        $signedPropertiesToDigest = $signedProperties->C14N();

        $xmlDigest = base64_encode(Tools::sha256($signedPropertiesToDigest));

        $reference2->appendChild($dom->createElementNS(Tools::NAMESPACE_DS, 'DigestValue', $xmlDigest));

        $actualDigest = '';
        openssl_sign(
            $signedInfo->C14N(),
            $actualDigest,
            $this->certificate->getPrivateKey(),
            'sha256WithRSAEncryption'
        );

        $signatureValue->textContent = chunk_split(base64_encode($actualDigest), 64, "\n");

        if ($signed = $dom->saveXML()) {
            return $signed;
        } else {
            throw new XadesException();
        }
    }
}
