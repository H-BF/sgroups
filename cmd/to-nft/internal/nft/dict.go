package nft

type dictItem[Tk comparable, Tv any] struct {
	k Tk
	v Tv
}

type dict[Tk comparable, Tv any] struct {
	data map[Tk]Tv
}

func (d *dict[Tk, Tv]) del(ks ...Tk) *dict[Tk, Tv] {
	if len(ks) > 0 && d.len() > 0 {
		for i := range ks {
			delete(d.data, ks[i])
		}
	}
	return d
}

func (d *dict[Tk, Tv]) putItems(its ...dictItem[Tk, Tv]) *dict[Tk, Tv] {
	if len(its) > 0 {
		d.ensureinited()
		for _, it := range its {
			d.put(it.k, it.v)
		}
	}
	return d
}

func (d *dict[Tk, Tv]) put(k Tk, v Tv) *dict[Tk, Tv] {
	d.ensureinited()
	d.data[k] = v
	return d
}

func (d *dict[Tk, Tv]) iterate(f func(k Tk, v Tv) bool) {
	for k, v := range d.data {
		if !f(k, v) {
			return
		}
	}
}

func (d *dict[Tk, Tv]) get(k Tk) (v Tv, ok bool) {
	if d.len() > 0 {
		v, ok = d.data[k]
	}
	return v, ok
}

func (d *dict[Tk, Tv]) at(k Tk) Tv {
	v, _ := d.get(k)
	return v
}

func (d *dict[Tk, Tv]) clear() {
	d.data = nil
}

func (d *dict[Tk, Tv]) len() int {
	return len(d.data)
}

func (d *dict[Tk, Tv]) ensureinited() {
	if d.data == nil {
		d.data = make(map[Tk]Tv)
	}
}
