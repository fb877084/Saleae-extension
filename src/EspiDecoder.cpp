#include "EspiDecoder.h"

static std::string HexByte( uint8_t b )
{
	char buf[8];
	snprintf( buf, sizeof( buf ), "0x%02X", b );
	return std::string( buf );
}

EspiDecodedTransaction EspiDecoder::Decode( const std::vector<uint8_t>& mosi, const std::vector<uint8_t>& miso )
{
	EspiDecodedTransaction out;
	out.mosi = mosi;
	out.miso = miso;

	if( mosi.empty() )
	{
		out.ok = false;
		out.summary = "eSPI: empty MOSI";
		return out;
	}

	// Stage 2: WAIT-state alignment (best-effort)
	// Many captures show long 0xFF runs on MISO before the response becomes valid.
	size_t rsp_off = 0;
	while( rsp_off < miso.size() && miso[ rsp_off ] == 0xFF )
		rsp_off++;

	std::string rsp0 = ( rsp_off < miso.size() ) ? HexByte( miso[ rsp_off ] ) : "(none)";

	// Header preview (until we implement full eSPI parsing)
	auto hb = [&]( size_t i ) -> std::string {
		if( i < mosi.size() )
			return HexByte( mosi[ i ] );
		return "--";
	};
	auto rb = [&]( size_t i ) -> std::string {
		if( rsp_off + i < miso.size() )
			return HexByte( miso[ rsp_off + i ] );
		return "--";
	};

	out.ok = true;
	out.summary = std::string( "eSPI(cmd=" ) + HexByte( mosi[ 0 ] ) +
		", hdr=[" + hb( 1 ) + " " + hb( 2 ) + " " + hb( 3 ) + " " + hb( 4 ) + "]" +
		", mosi_len=" + std::to_string( mosi.size() ) +
		", miso_len=" + std::to_string( miso.size() ) +
		", wait_ff=" + std::to_string( rsp_off ) +
		", rsp=[" + rb( 0 ) + " " + rb( 1 ) + " " + rb( 2 ) + " " + rb( 3 ) + "]" +
		", rsp0=" + rsp0 +
		")";
	return out;
}
