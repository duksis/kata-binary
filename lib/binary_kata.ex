defmodule BinaryKata do

  @doc """
  Should return `true` when given parameter start with UTF8 Byte-Order-Mark, otherwise `false`.
  @see https://en.wikipedia.org/wiki/Byte_order_mark
  """
  def has_utf8_bom?(<<0xef,0xbb,0xbf,_ :: binary>>), do: true
  def has_utf8_bom?(_), do: false

  @doc """
  Remove a UTF8 BOM if exists.
  """
  def remove_utf8_bom(<<0xef,0xbb,0xbf,rest :: binary>>), do: rest
  def remove_utf8_bom(<<everything :: binary>>), do: everything

  @doc """
  Add a UTF8 BOM if not exists.
  """
  def add_utf8_bom(everything = <<0xef,0xbb,0xbf,rest :: binary>>), do: everything
  def add_utf8_bom(everything), do: <<0xef,0xbb,0xbf>> <> everything

  @doc """
  Detecting types of images by their first bytes / magic numbers.

  @see https://en.wikipedia.org/wiki/JPEG
  @see https://en.wikipedia.org/wiki/Portable_Network_Graphics
  @see https://en.wikipedia.org/wiki/GIF
  """
  def image_type!(<<"GIF8" ,_ :: binary>>), do: :gif
  def image_type!(<<0x89, 0x50, 0x4e, 0x47,_ :: binary>>), do: :png
  def image_type!(<<0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, _ :: binary>>), do: :jfif
  def image_type!(_), do: :unknown

  @doc """
  Get the width and height from a GIF image.
  First 6 bytes contain the magic header.

  `width` will be little-endian in byte 7 and 8.
  `height` will be little-endian in byte 9 and 10.
  """
  def gif_dimensions!(<<"GIF", _version :: binary-size(3), width :: little-integer-size(16), height :: little-integer-size(16), _ :: binary>>) do
    {width, height}
  end
  def gif_dimensions!(_), do: :error

  @doc """
  Parsing Payload of a ARP packet. Padding will be omitted.

  @see https://en.wikipedia.org/wiki/Address_Resolution_Protocol
  """
  def parse_arp_packet_ipv4!(<<
    _ :: binary-size(7),
    operator :: little-integer-size(8),
    sender_address :: integer-size(48),
    spa1 :: integer-size(8),
    spa2 :: integer-size(8),
    spa3 :: integer-size(8),
    spa4 :: integer-size(8),
    target_address :: integer-size(48),
    tpa1 :: integer-size(8),
    tpa2 :: integer-size(8),
    tpa3 :: integer-size(8),
    tpa4 :: integer-size(8),_ :: binary
  >>) do
    {arp_operation_to_atom(operator), sender_address, {spa1, spa2, spa3, spa4}, target_address, {tpa1, tpa2, tpa3, tpa4}}
  end

  # Helper for `parse_arp_packet_ipv4!`
  defp arp_operation_to_atom(1), do: :request
  defp arp_operation_to_atom(2), do: :response

end
