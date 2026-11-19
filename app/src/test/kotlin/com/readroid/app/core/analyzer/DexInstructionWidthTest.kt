package com.readroid.app.core.analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class DexInstructionWidthTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun uleb(out: ByteArrayOutputStream, v: Int) {
        var value = v
        while (true) {
            val b = value and 0x7f
            value = value ushr 7
            if (value == 0) { out.write(b); return }
            out.write(b or 0x80)
        }
    }

    /** DEX com um método cujo corpo contém as instruções [insns] (unidades little-endian). */
    private fun apkWithInsns(vararg insns: Short): java.io.File {
        val out = ByteArrayOutputStream()
        val h = java.nio.ByteBuffer.allocate(112).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        h.put(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00))
        h.putInt(0); h.put(ByteArray(20)); h.putInt(0); h.putInt(112); h.putInt(0x12345678)
        h.putInt(0); h.putInt(0); h.putInt(0)
        h.putInt(2); h.putInt(112); h.putInt(1); h.putInt(120)
        h.putInt(0); h.putInt(0); h.putInt(0); h.putInt(0)
        h.putInt(1); h.putInt(124); h.putInt(1); h.putInt(132); h.putInt(0); h.putInt(0)
        out.write(h.array())
        val ids = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        ids.putInt(164).putInt(180); out.write(ids.array())
        val type = java.nio.ByteBuffer.allocate(4).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        type.putInt(0); out.write(type.array())
        val method = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        method.putShort(0).putShort(0).putInt(1); out.write(method.array())
        val cls = java.nio.ByteBuffer.allocate(32).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        cls.putInt(0).putInt(1).putInt(0xFFFFFFFF.toInt()).putInt(0xFFFFFFFF.toInt())
        cls.putInt(0).putInt(0).putInt(0).putInt(0) // class_data placeholder patched later
        out.write(cls.array())
        check(out.size() == 164)
        out.write(12); out.write("Lcom/demo/A;".toByteArray(Charsets.US_ASCII)); out.write(0)
        while (out.size() < 180) out.write(0)
        out.write(1); out.write("X".toByteArray(Charsets.US_ASCII)); out.write(0)
        while (out.size() < 196) out.write(0)
        val codeOffset = 196
        val code = java.nio.ByteBuffer.allocate(16 + insns.size * 2).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        code.putShort(2).putShort(0).putShort(0).putShort(0).putInt(0).putInt(insns.size)
        insns.forEach { code.putShort(it) }
        out.write(code.array())
        uleb(out, 0); uleb(out, 0); uleb(out, 1); uleb(out, 0)
        uleb(out, 0); uleb(out, 0x9); uleb(out, codeOffset)
        val bytes = out.toByteArray()
        java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(32, bytes.size)
        // patch class_data_off
        java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(160, codeOffset + 16 + insns.size * 2)
        val f = tmp.newFile("w-${System.nanoTime()}.apk")
        ZipOutputStream(f.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("classes.dex")); z.write(bytes)
        }
        return f
    }

    private fun linesOf(vararg insns: Short): List<String> {
        val apk = apkWithInsns(*insns)
        return DexInventoryReader.readMethodBody(apk, "classes.dex", 0).lines
    }

    @Test
    fun goto16AndIfZeroUseTwoUnitWidths() {
        val lines = linesOf(
            0x0029, 0x0005, // goto/16 +5
            0x0139, 0x0004, // if-nez v1, +4 (lands 0x6)
            0x000e          // return-void
        )
        assertEquals(listOf("goto/16 0x5", "if-nez v1, 0x6", "return-void"), lines)
    }

    @Test
    fun threeUnitConstDecodesAllOperands() {
        val lines = linesOf(
            0x0014, 0x3412, 0x7856.toShort(), // const v0 = 0x78563412
            0x000e
        )
        assertEquals("const v0, 0x78563412", lines[0])
        assertEquals("return-void", lines[1])
    }

    @Test
    fun binaryOpsUseThirdRegisterFromUnitOne() {
        val lines = linesOf(
            0x2090, 0x0003, // add-int v0, v2, v3 (G=2, C=3)
            0x000e
        )
        assertEquals("add-int v0, v2, v3", lines[0])
    }

    @Test
    fun packedSwitchPayloadSkipsCorrectly() {
        // packed-switch payload: ident=0x0100, size=1, first_key, targets[1]
        val lines = linesOf(
            0x002b, 0x0005, 0x0000, // packed-switch v0, +5 (31t)
            0x0100, 0x0001, 0x0000, 0x0000, 0x0001, 0x0002, // payload (6 units)
            0x000e
        )
        assertEquals("packed-switch v0, 0x5", lines[0])
        assertEquals("packed-switch-payload (1 case(s))", lines[1])
        assertEquals("return-void", lines[2])
    }

    @Test
    fun constStringAndInvokeUseExpectedWidths() {
        val lines = linesOf(
            0x001a, 0x0001, // const-string v0, @string/1
            0x1071, 0x0000, 0x0000, // invoke-static {}, @method/0
            0x000a, // move-result v0
            0x000e
        )
        assertEquals("const-string v0, @string/1", lines[0])
        assertEquals("invoke-static {}, @method/0", lines[1])
        assertEquals("move-result v0", lines[2])
        assertEquals("return-void", lines[3])
    }

    @Test
    fun truncationStillRespected() {
        val apk = apkWithInsns(*ShortArray(600) { 0x000e })
        val body = DexInventoryReader.readMethodBody(apk, "classes.dex", 0)
        assertTrue(body.truncated)
        assertEquals(401, body.lines.size)
    }
}
