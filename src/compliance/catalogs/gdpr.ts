import type { ControlDef } from '../types.js';

// GDPR — Regulation (EU) 2016/679 of the European Parliament and of the Council of 27 April 2016
// on the protection of natural persons with regard to the processing of personal data and on the
// free movement of such data, and repealing Directive 95/46/EC.
//
// Article headings and the quoted text of Art. 5(1)(f), 25 and 32(1)(a)-(d) verified 2026-08
// against the consolidated regulation text; the Official Journal (OJ L 119, 4.5.2016) is the
// canonical reference.
//
// Scope note: GDPR is a regulation about processing, not a technical control set, so only the
// articles that a read-only Salesforce org-configuration review can produce evidence for are
// catalogued. Articles covering lawful basis, data-subject rights, DPIAs (Art. 35), controller /
// processor contracts and supervisory-authority procedure are out of scope for this tool and
// deliberately absent — their absence is not a claim that they do not apply.
//
// Where a paragraph is mapped rather than a whole article (Art. 5(1)(f), Art. 32(1)(a)/(b)/(d)),
// the id names the paragraph so a finding cites the specific obligation, not the article at large.
const V = 'Regulation (EU) 2016/679';
const URL = 'https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng';
const ref = (cite: string): string => `Regulation (EU) 2016/679, ${cite}`;

export const GDPR_CONTROLS: ControlDef[] = [
  { id: 'GDPR-Art5(1)(f)', framework: 'GDPR', version: V,
    title: 'Integrity and confidentiality',
    requirement: 'Personal data shall be processed in a manner that ensures appropriate security of the personal data, including protection against unauthorised or unlawful processing and against accidental loss, destruction or damage, using appropriate technical or organisational measures.',
    sourceRef: ref('Art. 5(1)(f)'), url: URL, verified: true },
  { id: 'GDPR-Art25', framework: 'GDPR', version: V,
    title: 'Data protection by design and by default',
    requirement: 'The controller shall implement appropriate technical and organisational measures for ensuring that, by default, only personal data which are necessary for each specific purpose are processed — including their accessibility. Such measures shall ensure that by default personal data are not made accessible without the individual\'s intervention to an indefinite number of natural persons.',
    sourceRef: ref('Art. 25(1)-(2)'), url: URL, verified: true },
  { id: 'GDPR-Art30', framework: 'GDPR', version: V,
    title: 'Records of processing activities',
    requirement: 'Each controller shall maintain a record of processing activities under its responsibility, including the categories of personal data processed, the categories of recipients to whom the data have been disclosed, and transfers to third countries.',
    sourceRef: ref('Art. 30(1)'), url: URL, verified: true },
  { id: 'GDPR-Art32(1)(a)', framework: 'GDPR', version: V,
    title: 'Pseudonymisation and encryption of personal data',
    requirement: 'Taking account of the state of the art and the risks of the processing, the controller and processor shall implement appropriate technical and organisational measures including the pseudonymisation and encryption of personal data.',
    sourceRef: ref('Art. 32(1)(a)'), url: URL, verified: true },
  { id: 'GDPR-Art32(1)(b)', framework: 'GDPR', version: V,
    title: 'Ongoing confidentiality, integrity, availability and resilience',
    requirement: 'The controller and processor shall implement measures providing the ability to ensure the ongoing confidentiality, integrity, availability and resilience of processing systems and services.',
    sourceRef: ref('Art. 32(1)(b)'), url: URL, verified: true },
  { id: 'GDPR-Art32(1)(d)', framework: 'GDPR', version: V,
    title: 'Regular testing and evaluation of security measures',
    requirement: 'The controller and processor shall implement a process for regularly testing, assessing and evaluating the effectiveness of technical and organisational measures for ensuring the security of the processing.',
    sourceRef: ref('Art. 32(1)(d)'), url: URL, verified: true },
  { id: 'GDPR-Art33', framework: 'GDPR', version: V,
    title: 'Notification of a personal data breach to the supervisory authority',
    requirement: 'In the case of a personal data breach, the controller shall without undue delay and, where feasible, not later than 72 hours after having become aware of it, notify the breach to the competent supervisory authority. Detecting and characterising a breach is a precondition of meeting that deadline.',
    sourceRef: ref('Art. 33(1)'), url: URL, verified: true },
  { id: 'GDPR-Art44', framework: 'GDPR', version: V,
    title: 'General principle for transfers',
    requirement: 'Any transfer of personal data to a third country or international organisation shall take place only if the conditions of Chapter V are met, including onward transfers. All provisions of that chapter shall be applied to ensure the level of protection guaranteed by this Regulation is not undermined.',
    sourceRef: ref('Art. 44'), url: URL, verified: true },
];
