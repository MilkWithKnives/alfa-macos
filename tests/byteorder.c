/* Regression: table branch tokens must never become USB register writes. */
#include "drivers/rtw88/main.h"
#include "drivers/rtw88/phy.h"
#include "drivers/rtw88/rtw8821a.h"
#include "drivers/rtw88/rtw8821a_table.h"

static unsigned int writes, invalid;
static u32 last_data;

static void record_write(struct rtw_dev *dev, const struct rtw_table *tbl,
                         u32 addr, u32 data)
{
    (void) dev;
    (void) tbl;
    writes++;
    last_data = data;
    if (addr < 0x800 || addr > 0x1fff) {
        if (invalid < 5)
            printf("INVALID register write: 0x%08x = 0x%08x\n", addr, data);
        invalid++;
    }
}

int main(void)
{
    struct rtw_dev *dev = calloc(1, sizeof(*dev));
    if (!dev)
        return 2;
    dev->chip = &rtw8821a_hw_spec;
    dev->hal.phy_cond.intf = INTF_USB;

    const u32 conditional[] = {
        0x8000020c, 0, 0x40000000, 0,
        0x81c, 0x1111,
        0xa0000000, 0, 0x81c, 0x2222,
        0xb0000000, 0
    };
    const struct rtw_table synthetic = {
        .data = conditional, .size = ARRAY_SIZE(conditional),
        .parse = rtw_parse_tbl_phy_cond, .do_cfg = record_write
    };
    int failed = 0;
    for (int matched = 0; matched <= 1; matched++) {
        writes = invalid = 0;
        dev->hal.phy_cond.rfe = matched ? 12 : 0;
        rtw_load_table(dev, &synthetic);
        bool ok = writes == 1 && invalid == 0 &&
                  last_data == (matched ? 0x1111 : 0x2222);
        printf("IF/ELSE (%s): %s\n", matched ? "match" : "no match", ok ? "PASS" : "FAIL");
        failed |= !ok;
    }

    struct rtw_table actual = rtw8821a_agc_tbl;
    actual.do_cfg = record_write;
    writes = invalid = 0;
    dev->hal.phy_cond.rfe = 0;
    rtw_load_table(dev, &actual);
    printf("Actual RTL8821A AGC table: %u writes, %u invalid: %s\n",
           writes, invalid, writes && !invalid ? "PASS" : "FAIL");
    failed |= !writes || invalid != 0;
    free(dev);
    return failed;
}
