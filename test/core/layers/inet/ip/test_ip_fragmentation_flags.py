from unittest import TestCase

from nally.core.layers.inet.ip.ip_fragmentation_flags import IpFragmentationFlags


class TestIpFragmentationFlags(TestCase):

    IP_FLAGS_DF = 0b010  # Only DF flag set
    IP_FLAGS_MF = 0b001  # Only MF flag set
    IP_FLAGS_DF_MF = 0b011  # DF and MF flags set

    def test_flags(self):
        flags_df = IpFragmentationFlags(df=True)
        self.assertEqual(self.IP_FLAGS_DF, flags_df.flags)

        flags_mf = IpFragmentationFlags(mf=True)
        self.assertEqual(self.IP_FLAGS_MF, flags_mf.flags)

        flags_df_mf = IpFragmentationFlags(df=True, mf=True)
        self.assertEqual(self.IP_FLAGS_DF_MF, flags_df_mf.flags)

        no_flags = IpFragmentationFlags()
        self.assertEqual(0, no_flags.flags)

    def test_from_int(self):
        flags_df = IpFragmentationFlags.from_int(self.IP_FLAGS_DF)
        self.assertEqual(self.IP_FLAGS_DF, flags_df.flags)
        self.assertTrue(flags_df.is_flag_set(IpFragmentationFlags.DF))
        self.assertFalse(flags_df.is_flag_set(IpFragmentationFlags.MF))

        flags_mf = IpFragmentationFlags.from_int(self.IP_FLAGS_MF)
        self.assertEqual(self.IP_FLAGS_MF, flags_mf.flags)
        self.assertTrue(flags_mf.is_flag_set(IpFragmentationFlags.MF))
        self.assertFalse(flags_mf.is_flag_set(IpFragmentationFlags.DF))

        flags_df_mf = IpFragmentationFlags.from_int(self.IP_FLAGS_DF_MF)
        self.assertEqual(self.IP_FLAGS_DF_MF, flags_df_mf.flags)
        self.assertTrue(flags_df_mf.is_flag_set(IpFragmentationFlags.DF))
        self.assertTrue(flags_df_mf.is_flag_set(IpFragmentationFlags.MF))

        no_flags = IpFragmentationFlags.from_int(0)
        self.assertEqual(0, no_flags.flags)
        self.assertFalse(no_flags.is_flag_set(IpFragmentationFlags.DF))
        self.assertFalse(no_flags.is_flag_set(IpFragmentationFlags.MF))
