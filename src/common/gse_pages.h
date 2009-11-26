/****************************************************************************/
/**
 *   @file          gse_doc.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: DOC
 *
 *   @brief         Mainpage of the documentation
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

/**
 * \mainpage
 *
 * <h2>Introduction</h2>
 * 
 * <p>
 * This piece of software is an implementation of Generic Stream Encapsulation
 * for Linux (or other Unix-compatible OS). The library can be used to add GSE
 * encapsulation/deencapsulation capabilities to an application
 * </p>
 *
 *
 * <p>The list of features implemented (or not yet implemented) in the GSE
 * library is available on a separate page: \ref features</p>
 *
 * <p>The APIs for GSE encapsulation and deencapsulation are also available on
 * separate pages:
 *  <ul>
 *    <li>\ref gse_common</li>
 *    <li>\ref gse_encap</li>
 *    <li>\ref gse_deencap</li>
 *  </ul>
 * </p>
 * 
 * <h2>License</h2>
 * 
 * <p>
 * The sources are in the src directory. They are separated into
 * three subdirectories:
 *  <ul>
 *   <li>a directory that contains some common elements for encapsulation
 *       and deencapsulation</li>
 *   <li>a directory that contains the encapsulation functions</li>
 *   <li>a directory that contains the deencapsulation functions</li>
 *  </ul>
 * Each directory contains a test subdirectorie that contains nominal tests
 * for the elements of the directory.
 * </p>
 * 
 * 
 * <h2>Non-regression tests</h2>
 * 
 * <p>
 * The test directory contains test applications. See the header of the
 * test files for details.
 * </p>
 * 
 * <h2>References</h2>
 * 
 * <table style="border-collapse: collapse; border: solid thin black;">
 *  <tr>
 *   <td>ETSI TS 102 606</td>
 *   <td>
 *    <p>
 *     Digital Video Broadcasting (DVB);
 *     Generic Stream Encapsulation (GSE) Protocol
 *    </p>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>DVB Document A134</td>
 *   <td>
 *    <p>
 *     Generic Stream Encapsulation (GSE)
 *     Implementation Guidelines
 *    </p>
 *   </td>
 *  </tr>
 *  <tr>
 *   <td>IETF RFC 4326</td>
 *   <td>
 *    <p>
 *     Unidirectional Lightweight Encapsulation (ULE) for Transmission of IP
 *     Datagrams over an MPEG-2 Transport Stream (TS) 
 *    </p>
 *   </td>
 *  </tr>
 * </table>
 */

/**
 * \page features Library features
 *
 * <p>Unsupported features are in <span style="color: red;">red</span>.</p>
 * <p>Limitations are in <span style="color: orange;">orange</span>.</p>
 *
 * <h2>Main features</h2>
 *
 * <ul>
 *  <li>GSE encapsulation</li>
 *  <li>GSE deencapsulation</li>
 *  <li>GSE refragmentation</li>
 *  <li>
 *    Label Types:
 *    <ul>
 *     <li>6-Bytes Label</li>
 *     <li style="color: red;">3-Bytes Label</li>
 *     <li style="color: red;">No-Label</li>
 *     <li style="color: red;">Label re-use</li>
 *    </ul>
 *  </li>
 *  <li>
 *    Extensions:
 *    <ul>
 *     <li style="color: red;">Not implemented</li>
 *    </ul>
 *  </li>
 * </ul>
 *
 */


