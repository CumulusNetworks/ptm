/* Copyright 2011 Cumulus Networks Inc.  All rights reserved. */
/* See License file for licenese. */

#include "cumulus.h"

#include <string.h>
#include <assert.h>

#include "hash.h"

#include "hashtable.h"


enum _hash_table_op_s {
    _hash_table_op_add = 0,
    _hash_table_op_find,
    _hash_table_op_delete
};

static bool _hash_table_do_op(hash_table_t *ht, void *key, int key_size,
                       void **data, int op)
{
    hash_node_t* node;
    hash_node_t** prev;
    uint32_t key_hash;

    assert(key_size > 0);
    assert(key != NULL);

    key_hash = hash(key, key_size, 0) % ht->size;
    prev = &ht->nodes[key_hash];
    node = ht->nodes[key_hash];

    while (node) {
        if(node->key_size == key_size &&
           memcmp(node->key, key, key_size) == 0) {
            if ((data != NULL) &&
                (op != _hash_table_op_add)){
                *data = node->data;
            }
            if (op == _hash_table_op_delete) {
                *prev = node->next;
                free(node);
                ht->count--;
            }
            if (op == _hash_table_op_add) {
                return FALSE;
            } else {
                return TRUE;
            }
        }
        prev = &node->next;
        node = node->next;
    }

    if (op == _hash_table_op_add) {
        node = malloc(sizeof (*node));
        if (!node) {
            abort();
        }
        node->key = key;
        node->key_size = key_size;
        node->data = *data;
        node->next = ht->nodes[key_hash];
        ht->nodes[key_hash] = node;
        ht->count++;
        return TRUE;
    } else {
        if (data != NULL) {
            *data = NULL;
        }
        return FALSE;
    }
}

bool hash_table_add(hash_table_t *ht, void *key, int key_size, void *data)
{
    return _hash_table_do_op(ht, key, key_size, &data, _hash_table_op_add);
}

bool hash_table_find(hash_table_t *ht, void *key, int key_size, void **data)
{
    return _hash_table_do_op(ht, key, key_size, data, _hash_table_op_find);
}

bool hash_table_delete(hash_table_t *ht, void *key, int key_size, void **data)
{
    return _hash_table_do_op(ht, key, key_size, data, _hash_table_op_delete);
}

void hash_table_foreach(hash_table_t *ht,
                        int (*foreach_cb)(void *data, void *cbarg), void *cbarg)
{
    hash_node_t *node;
    hash_node_t *next;
    hash_node_t **prev;
    int i;
    int rv;

    for (i = 0; i < ht->size; i++) {
        node = ht->nodes[i];
        prev = &ht->nodes[i];
        while (node) {
            next = node->next;
            rv = foreach_cb(node->data, cbarg);
            if (rv == hash_table_foreach_delete) {
                *prev = next;
                free(node);
                ht->count--;
            } else {
                prev = &node->next;
            }
            node = next;
        }
    }
}


hash_table_t *hash_table_alloc(int size)
{
    hash_table_t *ht = calloc(1, sizeof (*ht));

    if (!ht) {
        abort();
    }
    ht->nodes = calloc(size, sizeof (*ht->nodes));
    if (!ht->nodes) {
        abort();
    }

    ht->size = size;

    return ht;
}


void hash_table_free(hash_table_t *ht, void (*free_cb)(void* data))
{
    int node_free_cb(void *data, void *cbarg) {
        if (free_cb != NULL) {
            free_cb(data);
        }
        return hash_table_foreach_delete;
    }

    hash_table_foreach( ht, node_free_cb, NULL);
    free(ht->nodes);
    free(ht);
}

int hash_table_count(hash_table_t *ht)
{
    return ht->count;
}
