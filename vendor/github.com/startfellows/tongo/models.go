package tongo

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/startfellows/tongo/boc"
	"github.com/startfellows/tongo/tlb"
)

var BlockchainInterfaceIsNil = errors.New("blockchain interface is nil")

// Grams
// nanograms$_ amount:(VarUInteger 16) = Grams;
type Grams uint64 // total value fit to uint64

const OneTON Grams = 1_000_000_000

func (g Grams) MarshalTLB(c *boc.Cell, tag string) error {
	var amount struct {
		Val tlb.VarUInteger `tlb:"16bytes"`
	}
	amount.Val = tlb.VarUInteger(*big.NewInt(int64(g)))
	err := tlb.Marshal(c, amount)
	return err
}

func (g *Grams) UnmarshalTLB(c *boc.Cell, tag string) error {
	var amount struct {
		Val tlb.VarUInteger `tlb:"16bytes"`
	}
	err := tlb.Unmarshal(c, &amount)
	if err != nil {
		return err
	}
	val := big.Int(amount.Val)
	if !val.IsUint64() {
		return fmt.Errorf("grams overflow")
	}
	*g = Grams(val.Uint64())
	return nil
}

func (g Grams) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%d\"", g)), nil
}

func (g *Grams) UnmarshalJSON(data []byte) error {
	val, err := strconv.ParseUint(string(bytes.Trim(data, "\" \n")), 10, 64)
	if err != nil {
		return err
	}
	*g = Grams(val)
	return nil
}

// CurrencyCollection
// currencies$_ grams:Grams other:ExtraCurrencyCollection
// = CurrencyCollection;
type CurrencyCollection struct {
	Grams Grams
	Other ExtraCurrencyCollection
}

// ExtraCurrencyCollection
// extra_currencies$_ dict:(HashmapE 32 (VarUInteger 32))
// = ExtraCurrencyCollection;
type ExtraCurrencyCollection struct {
	Dict tlb.HashmapE[struct {
		Val tlb.VarUInteger `tlb:"32bytes"`
	}] `tlb:"32bits"`
}

// HashUpdate
// update_hashes#72 {X:Type} old_hash:bits256 new_hash:bits256
// = HASH_UPDATE X;
type HashUpdate struct {
	Magic   tlb.Magic `tlb:"update_hashes#72"`
	OldHash Hash
	NewHash Hash
}

// SnakeData
// tail#_ {bn:#} b:(bits bn) = SnakeData ~0;
// cons#_ {bn:#} {n:#} b:(bits bn) next:^(SnakeData ~n) = SnakeData ~(n + 1);
type SnakeData boc.BitString

func (s SnakeData) MarshalTLB(c *boc.Cell, tag string) error {
	bs := boc.BitString(s)
	if c.BitsAvailableForWrite() < bs.GetWriteCursor() {
		s, err := bs.ReadBits(c.BitsAvailableForWrite())
		if err != nil {
			return err
		}
		err = c.WriteBitString(s)
		if err != nil {
			return err
		}
		ref := boc.NewCell()
		err = tlb.Marshal(ref, SnakeData(bs.ReadRemainingBits()))
		if err != nil {
			return err
		}
		err = c.AddRef(ref)
		return err
	}
	return c.WriteBitString(bs)
}

func (s *SnakeData) UnmarshalTLB(c *boc.Cell, tag string) error {
	b := c.ReadRemainingBits()
	if c.RefsAvailableForRead() > 0 {
		cell, err := c.NextRef()
		if err != nil {
			return err
		}
		var sn SnakeData
		err = tlb.Unmarshal(cell, &sn)
		if err != nil {
			return err
		}
		b.Append(boc.BitString(sn))
	}
	*s = SnakeData(b)
	return nil
}

// text#_ {n:#} data:(SnakeData ~n) = Text;
type Text string

func (t Text) MarshalTLB(c *boc.Cell, tag string) error {
	bs := boc.NewBitString(len(t) * 8)
	err := bs.WriteBytes([]byte(t))
	if err != nil {
		return err
	}
	return tlb.Marshal(c, SnakeData(bs))
}

func (t *Text) UnmarshalTLB(c *boc.Cell, tag string) error {
	var sn SnakeData
	err := tlb.Unmarshal(c, &sn)
	if err != nil {
		return err
	}
	bs := boc.BitString(sn)
	if bs.BitsAvailableForRead()%8 != 0 {
		return fmt.Errorf("text data must be a multiple of 8 bits")
	}
	b, err := bs.GetTopUppedArray()
	if err != nil {
		return err
	}
	*t = Text(b)
	return nil
}

// FullContent
// onchain#00 data:(HashMapE 256 ^ContentData) = FullContent;
// offchain#01 uri:Text = FullContent;
// text#_ {n:#} data:(SnakeData ~n) = Text;
type FullContent struct {
	tlb.SumType
	Onchain struct {
		Data tlb.HashmapE[tlb.Ref[ContentData]] `tlb:"256bits"`
	} `tlbSumType:"onchain#00"`
	Offchain struct {
		Uri SnakeData // Text
	} `tlbSumType:"offchain#01"`
}

// ContentData
// snake#00 data:(SnakeData ~n) = ContentData;
// chunks#01 data:ChunkedData = ContentData;
type ContentData struct {
	tlb.SumType
	Snake struct {
		Data SnakeData
	} `tlbSumType:"snake#00"`
	Chunks struct {
		Data ChunkedData
	} `tlbSumType:"chunks#01"`
}

func (c ContentData) Bytes() ([]byte, error) {
	var bs boc.BitString
	switch c.SumType {
	case "Snake":
		bs = boc.BitString(c.Snake.Data)
	case "Chunks":
		bs = boc.BitString(c.Chunks.Data)
	default:
		return nil, fmt.Errorf("empty content data struct")
	}
	if bs.BitsAvailableForRead()%8 != 0 {
		return nil, fmt.Errorf("data is not multiple of 8 bits")
	}
	return bs.GetTopUppedArray()
}

// ChunkedData
// chunked_data#_ data:(HashMapE 32 ^(SnakeData ~0)) = ChunkedData;
type ChunkedData boc.BitString

func (d ChunkedData) MarshalTLB(c *boc.Cell, tag string) error {
	// TODO: implement
	return fmt.Errorf("ChunkedData marshaling not implemented")
}

func (d *ChunkedData) UnmarshalTLB(c *boc.Cell, tag string) error {
	type chunkedData struct {
		Data tlb.HashmapE[tlb.Ref[SnakeData]] `tlb:"32bits"`
	}
	var (
		cd chunkedData
	)
	b := boc.NewBitString(boc.CellBits)
	err := tlb.Unmarshal(c, &cd)
	if err != nil {
		return err
	}
	// TODO: check keys sort
	for _, x := range cd.Data.Values() {
		b.Append(boc.BitString(x.Value))
	}
	*d = ChunkedData(b)
	return nil
}

type ShardDesc struct {
	tlb.SumType
	Old struct {
		SeqNo              uint32
		RegMcSeqno         uint32
		StartLT            uint64
		EndLT              uint64
		RootHash           Hash
		FileHash           Hash
		BeforeSplit        bool
		BeforeMerge        bool
		WantSplit          bool
		WantMerge          bool
		NXCCUpdated        bool
		Flags              uint32 `tlb:"3bits"`
		NextCatchainSeqNo  uint32
		NextValidatorShard int64
		MinRefMcSeqNo      uint32
		GenUTime           uint32
	} `tlbSumType:"old#b"`
	New struct {
		SeqNo              uint32
		RegMcSeqno         uint32
		StartLT            uint64
		EndLT              uint64
		RootHash           Hash
		FileHash           Hash
		BeforeSplit        bool
		BeforeMerge        bool
		WantSplit          bool
		WantMerge          bool
		NXCCUpdated        bool
		Flags              uint32 `tlb:"3bits"`
		NextCatchainSeqNo  uint32
		NextValidatorShard int64
		MinRefMcSeqNo      uint32
		GenUTime           uint32
	} `tlbSumType:"new#a"`
}

func (s ShardDesc) ToBlockId(workchain int32) TonNodeBlockIdExt {
	if s.SumType == "Old" {
		return TonNodeBlockIdExt{
			TonNodeBlockId: TonNodeBlockId{
				Workchain: workchain,
				Shard:     s.Old.NextValidatorShard,
				Seqno:     int32(s.Old.SeqNo),
			},
			RootHash: s.Old.RootHash,
			FileHash: s.Old.FileHash,
		}
	} else {
		return TonNodeBlockIdExt{
			TonNodeBlockId: TonNodeBlockId{
				Workchain: workchain,
				Shard:     s.New.NextValidatorShard,
				Seqno:     int32(s.New.SeqNo),
			},
			RootHash: s.New.RootHash,
			FileHash: s.New.FileHash,
		}
	}
}

type ShardInfoBinTree struct {
	BinTree tlb.BinTree[ShardDesc] `tlb:"32bits"`
}
type AllShardsInfo struct {
	ShardHashes tlb.HashmapE[tlb.Ref[ShardInfoBinTree]] `tlb:"32bits"`
}

type JettonMetadata struct {
	Uri         string `json:"uri,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Image       string `json:"image,omitempty"`
	ImageData   []byte `json:"image_data,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	Decimals    string `json:"decimals,omitempty"`
}
