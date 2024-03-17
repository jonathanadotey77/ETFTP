#ifndef LFUCACHE_H
#define LFUCACHE_H

#include <list>
#include <unordered_map>

template <class Key, class Value>
class LFUCache
{
private:
    using Entry = std::pair<Key, Value>;
    using EntryIterator = typename std::list<std::pair<Key, Value>>::iterator;

    std::unordered_map<Key, EntryIterator> table;
    std::list<Entry> queue;
    size_t maxCapacity;

public:
    LFUCache(size_t capacity = 1024) : maxCapacity(capacity) {}

    size_t size() const;
    Value *get(const Key &key);
    void put(const Key &key, const Value &value);
};

template <class Key, class Value>
size_t LFUCache<Key, Value>::size() const
{
    return queue.size();
}

template <class Key, class Value>
Value *LFUCache<Key, Value>::get(const Key &key)
{
    if (table.find(key) == table.end())
    {
        return NULL;
    }

    EntryIterator itr = table[key];
    queue.push_front(*itr);
    queue.erase(itr);
    table[key] = queue.begin();

    return &(queue.front().second);
}

template <class Key, class Value>
void LFUCache<Key, Value>::put(const Key &key, const Value &value)
{
    if (table.find(key) == table.end())
    {
        queue.push_front({key, value});
        table[key] = queue.begin();
    }
    else
    {
        EntryIterator itr = table[key];
        queue.push_front(*itr);
        queue.front().second = value;
        queue.erase(itr);
        table[key] = queue.begin();
    }

    if (queue.size() > this->maxCapacity)
    {
        table.erase(queue.back().first);
        queue.pop_back();
    }
}

#endif