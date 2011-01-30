// Ext2Attribute.cpp : implementation file
//

#include "stdafx.h"
#include "ext2mgr.h"
#include "Ext2Attribute.h"
#include "Ext2MgrDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CExt2Attribute dialog


CExt2Attribute::CExt2Attribute(CWnd* pParent /*=NULL*/)
        : CDialog(CExt2Attribute::IDD, pParent)
{
    //{{AFX_DATA_INIT(CExt2Attribute)
    m_Codepage = _T("");
    m_bReadonly = FALSE;
    m_DrvLetter = _T("");
    m_sPrefix = _T("");
    m_sSuffix = _T("");
    m_bAutoMount = FALSE;
    m_bFixMount = FALSE;
    m_sAutoMp = _T("");
    m_drvChar = 0;
    //}}AFX_DATA_INIT

    m_MainDlg = NULL;
    m_EVP = NULL;
    m_DevName = _T("");
    m_bCdrom = FALSE;
    m_cLetter = 0;
}


void CExt2Attribute::DoDataExchange(CDataExchange* pDX)
{
    CDialog::DoDataExchange(pDX);
    //{{AFX_DATA_MAP(CExt2Attribute)
    DDX_CBString(pDX, IDC_COMBO_CODEPAGE, m_Codepage);
    DDX_Check(pDX, IDC_READ_ONLY, m_bReadonly);
    DDX_CBString(pDX, IDC_COMBO_DRVLETTER, m_DrvLetter);
    DDX_Text(pDX, IDC_EXT2_PREFIX, m_sPrefix);
    DDV_MaxChars(pDX, m_sPrefix, 31);
    DDX_Text(pDX, IDC_EXT2_SUFFIX, m_sSuffix);
    DDV_MaxChars(pDX, m_sSuffix, 31);
    DDX_Check(pDX, IDC_AUTOMOUNT, m_bAutoMount);
    DDX_Check(pDX, IDC_FIXMOUNT, m_bFixMount);
    DDX_CBString(pDX, IDC_COMBO_AUTOMP, m_sAutoMp);
    //}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CExt2Attribute, CDialog)
    //{{AFX_MSG_MAP(CExt2Attribute)
    ON_BN_CLICKED(IDC_AUTOMOUNT, OnAutomount)
    ON_BN_CLICKED(IDC_FIXMOUNT, OnFixmount)
    //}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CExt2Attribute message handlers

BOOL CExt2Attribute::OnInitDialog()
{
    int i = 0;
    CString s;

    CDialog::OnInitDialog();

    m_Codepage = m_EVP->Codepage;
    m_bReadonly = m_EVP->bReadonly || m_bCdrom;
    if (m_bCdrom) {
        SET_WIN(IDC_READ_ONLY, FALSE);
    }

    if (m_bCdrom) {
        m_cLetter = Ext2QueryMountPoint(m_DevName.GetBuffer(MAX_PATH));
    } else {
        m_cLetter = Ext2QueryRegistryMountPoint(
                        m_DevName.GetBuffer(MAX_PATH));
    }

    if (m_cLetter) {
        m_bFixMount = TRUE;
        m_DrvLetter.Format("%c:", m_cLetter);
    } else {
        m_DrvLetter = "  ";
    }

    m_sPrefix = m_EVP->sHidingPrefix;
    m_sSuffix = m_EVP->sHidingSuffix;

    CComboBox   *cbCodepage = (CComboBox *)GetDlgItem(IDC_COMBO_CODEPAGE);
    if (cbCodepage) {
        cbCodepage->ResetContent();
        i = 0;
        while (gCodepages[i]) {
            cbCodepage->AddString(gCodepages[i++]);
        }
    }

    m_drvChar = Ext2QueryMountPoint(m_DevName.GetBuffer(MAX_PATH));

    {
        CComboBox   *cbDrvLetter = (CComboBox *)GetDlgItem(IDC_COMBO_DRVLETTER);
        CComboBox   *cbAutoLetter = (CComboBox *)GetDlgItem(IDC_COMBO_AUTOMP);

        PEXT2_LETTER drvLetter = NULL;
        cbDrvLetter->AddString("  ");
        cbAutoLetter->AddString("  ");

        if (m_drvChar) {
            m_sAutoMp.Format("%C:", m_drvChar);
            cbAutoLetter->AddString(m_sAutoMp);
        }

        if (m_cLetter) {
            cbDrvLetter->AddString(m_DrvLetter);
        }
        for (i=2; i < 26; i++) {
            drvLetter = &drvLetters[i];
            if (!drvLetter->bUsed) {
                s.Format("%c:", drvLetter->Letter);
                cbDrvLetter->AddString(s);
                cbAutoLetter->AddString(s);
            }
        }
        for (i=0; i < 10; i++) {
            drvLetter = &drvDigits[i];
            if (!drvLetter->bUsed) {
                s.Format("%c:", drvLetter->Letter);
                cbDrvLetter->AddString(s);
            }
        }
    }

    if (m_EVP->DrvLetter) {
        m_bAutoMount = TRUE;
    }

    SET_CHECK(IDC_AUTOMOUNT, m_bAutoMount);
    SET_CHECK(IDC_FIXMOUNT,  m_bFixMount);

    SET_WIN(IDC_COMBO_DRVLETTER, m_bFixMount);
    SET_WIN(IDC_COMBO_AUTOMP, m_bAutoMount);

    UpdateData(FALSE);

    return TRUE;  // return TRUE unless you set the focus to a control
    // EXCEPTION: OCX Property Pages should return FALSE
}

void CExt2Attribute::OnCancel()
{
    // TODO: Add extra cleanup here

    CDialog::OnCancel();
}

void CExt2Attribute::OnOK()
{
    BOOLEAN rc = FALSE;
    BOOLEAN dc = FALSE;

    NT::NTSTATUS status;
    HANDLE  Handle = NULL;
    CHAR    DrvLetter = 0;
    CString str;

    UpdateData(TRUE);

    if (m_Codepage.IsEmpty()) {
        m_Codepage = "default";
    }

    CComboBox *cbCodepage = (CComboBox *)GetDlgItem(IDC_COMBO_CODEPAGE);
    if (cbCodepage) {
        int rc = cbCodepage->FindStringExact(-1, m_Codepage);
        if (rc == CB_ERR) {
            AfxMessageBox("Invalid codepage type: "+m_Codepage, MB_OK|MB_ICONWARNING);
            return;
        }
    }

    if (m_EVP->bReadonly && m_EVP->bExt3 && !m_bReadonly) {
        str = "Are you sure to enable writing support"
              " on this EXT3 volume with Ext2Fsd ?";
        if (AfxMessageBox(str, MB_YESNO) != IDYES) {
            m_EVP->bExt3Writable = FALSE;
        } else {
            m_EVP->bExt3Writable = TRUE;
        }
    }

    /* initialize structures to communicate with ext2fsd service*/
    m_EVP->Magic = EXT2_VOLUME_PROPERTY_MAGIC;
    m_EVP->Command = APP_CMD_SET_PROPERTY2;
    m_EVP->Flags = 0;
    m_EVP->bReadonly = m_bReadonly;
    memset(m_EVP->Codepage, 0, CODEPAGE_MAXLEN);
    strcpy((CHAR *)m_EVP->Codepage, m_Codepage.GetBuffer(CODEPAGE_MAXLEN));

    /* initialize hiding filter patterns */
    if (m_sPrefix.IsEmpty()) {
        m_EVP->bHidingPrefix = FALSE;
        memset(m_EVP->sHidingPrefix, 0, HIDINGPAT_LEN);
    } else {
        strcpy( m_EVP->sHidingPrefix,
                m_sPrefix.GetBuffer(m_sPrefix.GetLength()));
        m_EVP->bHidingPrefix = TRUE;
    }

    if (m_sSuffix.IsEmpty()) {
        m_EVP->bHidingSuffix = FALSE;
        memset(m_EVP->sHidingSuffix, 0, HIDINGPAT_LEN);
    } else {
        strcpy(m_EVP->sHidingSuffix,
               m_sSuffix.GetBuffer(m_sSuffix.GetLength()));
        m_EVP->bHidingSuffix = TRUE;
    }

    if (!m_DrvLetter.IsEmpty() && m_DrvLetter.GetAt(0) != ' ') {
        DrvLetter = m_DrvLetter.GetAt(0);
    } else {
        DrvLetter = 0;
    }

    if (DrvLetter != m_cLetter || FALSE == m_bFixMount) {
        if (m_cLetter != 0) {
            Ext2SetRegistryMountPoint(&m_cLetter, NULL, FALSE);
            dc = TRUE;
        }
    }

    if (m_bFixMount) {
        if (DrvLetter) {

            PEXT2_LETTER drvLetter = NULL;

            if (DrvLetter >= '0' && DrvLetter <= '9') {
                drvLetter = &drvDigits[DrvLetter - '0'];
            } else if (DrvLetter >= 'A' && DrvLetter <= 'Z') {
                drvLetter = &drvLetters[DrvLetter - 'A'];
            } else if (DrvLetter >= 'a' && DrvLetter <= 'z') {
                drvLetter = &drvLetters[DrvLetter - 'a'];
            }

            Ext2SetRegistryMountPoint(&DrvLetter,
                                      m_DevName.GetBuffer(MAX_PATH), TRUE);
            if (drvLetter) {
                Ext2AssignDrvLetter(drvLetter, m_DevName.GetBuffer(MAX_PATH), FALSE);
            }
            dc = TRUE;
        }
    }

    if (m_bAutoMount && !m_bCdrom) {

        m_EVP->DrvLetter = m_sAutoMp.GetAt(0);
        if (m_EVP->DrvLetter > 'Z' || m_EVP->DrvLetter < 'A') {
            m_EVP->DrvLetter = 0;
        }
        m_EVP->DrvLetter |= 0x80;
        Ext2StorePropertyinRegistry(m_EVP);

        if (m_EVP->DrvLetter != 0xFF && m_sAutoMp.GetAt(0) != ' ' &&
                m_drvChar != m_sAutoMp.GetAt(0) ) {
            if (Ext2RefreshVolumePoint(
                        m_DevName.GetBuffer(MAX_PATH),
                        m_EVP->DrvLetter)) {
                m_EVP->DrvLetter = 0xFF;
            }
        }
    } else {
        m_EVP->DrvLetter = 0;
        Ext2StorePropertyinRegistry(m_EVP);
    }

    status = Ext2Open(m_DevName.GetBuffer(m_DevName.GetLength()),
                      &Handle, EXT2_DESIRED_ACCESS);
    if (!NT_SUCCESS(status)) {
        str.Format("Ext2Fsd service is not started.\n");
        AfxMessageBox(str, MB_OK | MB_ICONSTOP);
        rc = TRUE;
        goto errorout;
    }

    rc = Ext2SetExt2Property(Handle, m_EVP);

    if (rc) {

        str = "Ext2 volume settings updated successfully!";
        if (dc) {
            str += "\r\n\r\nFixed mountpoint needs reboot to take into affect.";
        }
        AfxMessageBox(str, MB_OK | MB_ICONINFORMATION);

    } else {
        AfxMessageBox("Failed to save the Ext2 settings !",
                      MB_OK | MB_ICONWARNING);
    }

errorout:

    Ext2Close(&Handle);

    if (rc) {
        CDialog::OnOK();
    }
}

void CExt2Attribute::OnAutomount()
{
    UpdateData(TRUE);
    SET_WIN(IDC_COMBO_AUTOMP, m_bAutoMount);
    /*
        if (m_bAutoMount) {
            AfxMessageBox("This function is still in experiment. You'd better set a\r\n"
                       "fixed mountpoint for fixed disk or set partition type to\r\n"
                       "0x07 (NTFS) or FAT for non-bootable partition. For removable\r\n"
                       "disks like usb-disk it's better to use the second method.");
        }
    */

    if (m_bAutoMount) {
        /*
                CComboBox *cbAutoLetter = (CComboBox *)GetDlgItem(IDC_COMBO_AUTOMP);
                if (cbAutoLetter && cbAutoLetter->GetCurSel() == CB_ERR) {
                    cbAutoLetter->SetCurSel(1);
                }
        */
        m_bFixMount = FALSE;
        SET_CHECK(IDC_FIXMOUNT,  FALSE);
        SET_WIN(IDC_COMBO_DRVLETTER, FALSE);

        UpdateData(FALSE);
    }
}

void CExt2Attribute::OnFixmount()
{
    UpdateData(TRUE);
    SET_WIN(IDC_COMBO_DRVLETTER, m_bFixMount);

    if (m_bFixMount) {
        /*
        	    CComboBox *cbDrvLetter = (CComboBox *)GetDlgItem(IDC_COMBO_DRVLETTER);
                if (cbDrvLetter && cbDrvLetter->GetCurSel() == CB_ERR) {
                    cbDrvLetter->SetCurSel(1);
                }
        */
        m_bAutoMount = FALSE;
        SET_CHECK(IDC_AUTOMOUNT, FALSE);
        SET_WIN(IDC_COMBO_AUTOMP, FALSE);

        UpdateData(FALSE);
    }
}

